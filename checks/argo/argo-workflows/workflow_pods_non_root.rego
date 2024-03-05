# METADATA
# title: "ensure workflow pods are running as non root"
# description: "Ensure Workflow pods are running as non root"
# scope: package
# related_resources:
# - https://argo-workflows.readthedocs.io/en/latest/workflow-pod-security-context/
# custom:
#   id: ARGOWF0004
#   avd_id: AVD-ARGOWF-0004
#   severity: HIGH 
#   provider: Kubernetes
#   short_code: non-root-argowf
#   recommended_action: "Ensure pods are running as non root"
package builtin.argowf.ARGOWF0004

deny[msg] {
    input.kind == "Workflow"
    not input.spec.securityContext.runAsNonRoot
    msg = result.new("Workflow should not run as root and securityContext.runAsNonRoot for the workflow should be set to true.", input.spec.securityContext.runAsNonRoot)
}

deny[msg] {
    input.kind == "Workflow"
    input.spec.securityContext.runAsNonRoot != true
    msg = result.new("Workflow should not run as root and securityContext.runAsNonRoot for the workflow should be set to true.", input.spec.securityContext.runAsNonRoot) 
}