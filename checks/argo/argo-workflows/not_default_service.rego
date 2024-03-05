# METADATA
# title: "default ServiceAccount not allowed"
# description: "Ensure Workflow pods are not using the default serviceAccountName"
# scope: package
# related_resources:
# - https://argo-workflows.readthedocs.io/en/latest/workflow-pod-security-context/
# custom:
#   id: ARGOWF0003
#   avd_id: AVD-ARGOWF-0003
#   severity: HIGH 
#   provider: Kubernetes
#   short_code: default-serviceaccount-not-allowed 
#   recommended_action: "Default ServiceAccount not allowed"
package builtin.argowf.ARGOWF0003

deny[msg] {
    input.kind == "Workflow"
    not input.spec.serviceAccountName
    msg := result.new("Ensure Workflow pods are not using the default ServiceAccount", input.spec.serviceAccountName)
}

deny[msg] {
    input.kind == "Workflow"
    input.spec.serviceAccountName == "default"
    msg := result.new("Ensure Workflow pods are not using the default ServiceAccount", input.spec.serviceAccountName)
}