//go:build image_smoke

package smoke

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func vulnerabilityReportCRD() *apiextensionsv1.CustomResourceDefinition {
	preserveUnknownFields := true
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vulnerabilityreports.aquasecurity.github.io",
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "aquasecurity.github.io",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Plural:   "vulnerabilityreports",
				Singular: "vulnerabilityreport",
				Kind:     "VulnerabilityReport",
				ListKind: "VulnerabilityReportList",
			},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{
					Name:    "v1alpha1",
					Served:  true,
					Storage: true,
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
							Type:                   "object",
							XPreserveUnknownFields: &preserveUnknownFields,
						},
					},
				},
			},
		},
	}
}
