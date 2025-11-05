package provider

import (
	"context"
	"fmt"
	"reflect"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/terraform-providers/terraform-provider-smc/internal/customfield"
)

type ResourceModelBase struct {
}

// dereferenceValue safely dereferences a pointer value
func dereferenceValue(val reflect.Value) reflect.Value {
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return reflect.Value{}
		}
		return val.Elem()
	}
	return val
}

// MergeResourceModelsWithContext copies fields from src to dest if they have the `fpro` tag.
// It handles nested structs, lists of structs, and pointers, with context for logging.
func MergeResourceModels(ctx context.Context, src, dest any, attrs ...string) error {
	return mergeStructs(ctx, reflect.ValueOf(src), reflect.ValueOf(dest), attrs...)
}

func mergeStructs(ctx context.Context, srcVal, destVal reflect.Value, attrs ...string) error {
	srcVal = dereferenceValue(srcVal)
	destVal = dereferenceValue(destVal)

	if !srcVal.IsValid() || !destVal.IsValid() {
		tflog.Debug(ctx, "invalid srcVal or destVal")
		return fmt.Errorf("invalid srcVal or destVal")
	}
	tflog.Debug(ctx, "entering mergeStructs", map[string]interface{}{
		"srcVal_kind": srcVal.Kind().String(),
	})
	if srcVal.Type() != destVal.Type() {
		return fmt.Errorf("type mismatch: %s vs %s", srcVal.Type(), destVal.Type())
	}

	if srcVal.Kind() == reflect.Struct {
		for i := 0; i < srcVal.NumField(); i++ {
			srcField := srcVal.Field(i)
			destField := destVal.Field(i)
			fieldType := srcVal.Type().Field(i)

			tflog.Debug(ctx, "processing srcField", map[string]interface{}{
				"field_name": srcVal.Type().Field(i).Name,
			})
			tag := fieldType.Tag.Get("fpro")
			if tag != "" {
				if len(attrs) > 0 && (!slices.Contains(attrs, tag)) {
					continue
				}

				tflog.Debug(ctx, "merging field with fpro tag", map[string]interface{}{
					"field_name": fieldType.Name,
				})
				destField.Set(srcField)
				if tag == "link" {
					copyLinkField(ctx, srcField, destVal)
				}
				continue
			}

			switch srcField.Kind() {
			case reflect.Ptr:
				if destField.IsNil() {
					tflog.Debug(ctx, "ignoring destField - is nil", map[string]interface{}{
						"field_name": fieldType.Name,
					})
					continue
				}
				mergeStructs(ctx, srcField, destField, attrs...)
			case reflect.Slice:
				err := mergeStructs(ctx, srcField, destField, attrs...)
				if err != nil {
					return err
				}
			case reflect.Struct:
				if srcField.Type() == reflect.TypeOf(types.String{}) ||
					srcField.Type() == reflect.TypeOf(types.Bool{}) ||
					srcField.Type() == reflect.TypeOf(types.Int64{}) {
					tflog.Debug(ctx, "ignoring terraform types field", map[string]interface{}{
						"field_name": fieldType.Name,
						"field_type": srcField.Type().String(),
					})
					continue
				}

				err := mergeStructs(ctx, srcField, destField)
				if err != nil {
					return err
				}
			}
		}
	} else if srcVal.Kind() == reflect.Slice {
		return mergeSlice(ctx, srcVal, destVal, attrs...)
	}
	return nil
}

func copyLinkField(ctx context.Context, srcField, destVal reflect.Value) error {
	lkField := destVal.FieldByName("Lk")

	elements := make(map[string]attr.Value)
	link := srcField.Interface().(customfield.NestedObjectList[ApiLinkResourceModel])

	if !link.IsNullOrUnknown() {
		links, diags := link.AsStructSliceT(ctx)
		if diags.HasError() {
			return fmt.Errorf("failed to convert links to struct slice: %v", diags)
		}

		for _, link := range links {
			if !link.Rel.IsNull() && !link.Href.IsNull() {
				elements[link.Rel.ValueString()] = link.Href
			}
		}

	}

	elementsMap, _ := customfield.NewMap[types.String](ctx, elements)
	lkField.Set(reflect.ValueOf(elementsMap))
	return nil
}

// GetElementId extracts an identifier from a struct value by looking for known ID fields
// or recursively searching through nested structs. It supports types.String and types.Int64 fields.
func GetElementId(val reflect.Value) (string, error) {
	// Dereference pointer if needed
	val = dereferenceValue(val)
	if !val.IsValid() || val.Kind() != reflect.Struct {
		return "", fmt.Errorf("value must be a valid struct, got %s", val.Kind())
	}

	// First, try to find known ID fields directly
	if id, found := findKnownIdField(val); found {
		return id, nil
	}

	// If no direct ID field found, recursively search nested structs
	return findNestedId(val)
}

// findKnownIdField searches for predefined ID field names in the struct
func findKnownIdField(val reflect.Value) (string, bool) {
	knownIdFields := []string{"InterfaceId", "Nodeid", "Name"}

	for _, fieldName := range knownIdFields {
		if id, err := extractFieldValue(val, fieldName); err == nil {
			return id, true
		}
	}
	return "", false
}

// extractFieldValue extracts and formats a field value as a string
func extractFieldValue(val reflect.Value, fieldName string) (string, error) {
	fieldVal := val.FieldByName(fieldName)
	if !fieldVal.IsValid() {
		return "", fmt.Errorf("field %s not found", fieldName)
	}

	switch fieldVal.Type() {
	case reflect.TypeOf(types.String{}):
		return fieldVal.Interface().(types.String).ValueString(), nil
	case reflect.TypeOf(types.Int64{}):
		return fmt.Sprintf("%s/%d", fieldName, fieldVal.Interface().(types.Int64).ValueInt64()), nil
	default:
		return "", fmt.Errorf("field %s has unsupported type %s", fieldName, fieldVal.Type())
	}
}

// findNestedId recursively searches through struct fields for an ID
func findNestedId(val reflect.Value) (string, error) {
	for i := 0; i < val.NumField(); i++ {
		fieldVal := val.Field(i)
		fieldType := val.Type().Field(i)

		// Skip invalid fields and anonymous (embedded) fields
		if !fieldVal.IsValid() || fieldType.Anonymous {
			continue
		}

		// Dereference pointer fields
		fieldVal = dereferenceValue(fieldVal)
		if !fieldVal.IsValid() {
			continue
		}

		// Recursively search struct fields
		if fieldVal.Kind() == reflect.Struct && !isTypesField(fieldVal.Type()) {
			if nestedId, err := GetElementId(fieldVal); err == nil {
				return fmt.Sprintf("%s/%s", fieldType.Name, nestedId), nil
			}
		}
	}

	return "", fmt.Errorf("no known ID field found in type %s", val.Type().Name())
}

// isTypesField checks if the field is a Terraform types field that should not be recursed into
func isTypesField(t reflect.Type) bool {
	return t == reflect.TypeOf(types.String{}) ||
		t == reflect.TypeOf(types.Bool{}) ||
		t == reflect.TypeOf(types.Int64{})
}

// mergeSlice merges two slices of structs by matching elements based on their IDs
func mergeSlice(ctx context.Context, srcVal, destVal reflect.Value, attrs ...string) error {
	if srcVal.Len() == 0 {
		tflog.Debug(ctx, "ignoring empty srcField", map[string]interface{}{
			"type_name": srcVal.Type().Name(),
		})
		return nil
	}

	for j := 0; j < srcVal.Len(); j++ {
		srcValElt := srcVal.Index(j)
		srcValElt = dereferenceValue(srcValElt)
		id, err := GetElementId(srcValElt)
		if err != nil {
			return err
		}

		destValElt, err := GetElementById(destVal, id)
		if err != nil {
			return err
		}
		err = mergeStructs(ctx, srcValElt, destValElt, attrs...)
		if err != nil {
			return err
		}
	}

	return nil
}

func GetElementById(destVal reflect.Value, id string) (reflect.Value, error) {
	for i := 0; i < destVal.Len(); i++ {
		destId, err := GetElementId(destVal.Index(i))
		if err != nil {
			return reflect.Value{}, err
		}
		if destId == id {
			return destVal.Index(i), nil
		}
	}
	return reflect.Value{}, fmt.Errorf("element with id %s not found", id)
}
