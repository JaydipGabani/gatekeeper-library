---
id: requiredlabels
title: Required Labels
---

# Required Labels

## Description
Requires resources to contain specified labels, with values matching provided regular expressions.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
  annotations:
    metadata.gatekeeper.sh/title: "Required Labels"
    metadata.gatekeeper.sh/version: 1.1.2
    description: >-
      Requires resources to contain specified labels, with values matching
      provided regular expressions.
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema: # schema of constraint.spec.parameter
          type: object
          properties:
            message: # violation message to be displayed
              type: string
            labels: # list of required labels and regex defining "allowed values"
              type: array
              description: >-
                A list of labels and values the object must specify.
              items:
                type: object
                properties:
                  key: # Required label key
                    type: string
                    description: >-
                      The required label.
                  allowedRegex: # Regex to define "allowed" value for labels
                    type: string
                    description: >-
                      If specified, a regular expression the annotation's value
                      must match. The value must contain at least one match for
                      the regular expression.
  targets:
    - target: admission.k8s.gatekeeper.sh
      code:
      - engine: K8sNativeValidation
        source:
          validations:
          # `variables.anyObject` is the object under review.
          # `variables.params` is parameters passed under `constraint.spec`
          # The expression iterates over all the labels passed in constraint parameters and verifies existence of required label key against all labels present in the object. If all the required labels are not present on the object metadata, expression results in false, and the object is rejected with the respective violation message.
          - expression: '(has(variables.anyObject.metadata) && variables.params.labels.all(entry, has(variables.anyObject.metadata.labels) && entry.key in variables.anyObject.metadata.labels))'
            messageExpression: '"missing required label, requires all of: " + variables.params.labels.map(entry, entry.key).join(", ")'
          # The expression iterates over all the labels passed in constraint parameters and verifies existence of required label key as well as verifies that required label value matches with "allowed regex".
          - expression: '(has(variables.anyObject.metadata) && variables.params.labels.all(entry, has(variables.anyObject.metadata.labels) && entry.key in variables.anyObject.metadata.labels && (!has(entry.allowedRegex) || string(variables.anyObject.metadata.labels[entry.key]).matches(string(entry.allowedRegex)))))'
            message: "regex mismatch"
      - engine: Rego
        source:
          rego: |
            package k8srequiredlabels

            get_message(parameters, _default) := _default {
              not parameters.message
            }

            get_message(parameters, _) := parameters.message

            # check for missing labels
            violation[{"msg": msg, "details": {"missing_labels": missing}}] {
              # input.review.object is the object under review
              # provided contains all the labels present on the object
              provided := {label | input.review.object.metadata.labels[label]}

              # input.parameters is `constraint.spec.parameters`
              # required contains all the required labels that are mention in constraint
              required := {label | label := input.parameters.labels[_].key}

              # check for any missing labels
              missing := required - provided
              count(missing) > 0
              def_msg := sprintf("you must provide labels: %v", [missing])
              msg := get_message(input.parameters, def_msg)
            }

            # check for regex violations
            violation[{"msg": msg}] {
              # iterate over key, value of each label
              value := input.review.object.metadata.labels[key]

              # iterate over all required labels
              expected := input.parameters.labels[_]

              # match required label key
              expected.key == key
              # do not match if allowedRegex is not defined, or is an empty string
              expected.allowedRegex != ""

              # Deny if label value does not match allowed regex.
              not regex.match(expected.allowedRegex, value)
              def_msg := sprintf("Label <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
              msg := get_message(input.parameters, def_msg)
            }


```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredlabels/template.yaml
```
## Examples
<details>
<summary>must-have-owner</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: all-must-have-owner
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
  parameters:
    message: "All namespaces must have an `owner` label that points to your company username"
    labels:
      - key: owner
        allowedRegex: "^[a-zA-Z]+.agilebank.demo$"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredlabels/samples/all-must-have-owner/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: allowed-namespace
  labels:
    owner: user.agilebank.demo

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredlabels/samples/all-must-have-owner/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: disallowed-namespace

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredlabels/samples/all-must-have-owner/example_disallowed.yaml
```

</details>
<details>
<summary>example-disallowed-label-value</summary>

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: disallowed-namespace
  labels:
    owner: user

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredlabels/samples/all-must-have-owner/example_disallowed_label_value.yaml
```

</details>


</details><details>
<summary>must-have-key</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: must-have-pizza
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    message: "All pods must have label of key `pizza` regardless of the label's value"
    labels:
      - key: pizza

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredlabels/samples/verify-label-key-only/constraint.yaml
```

</details>

<details>
<summary>label-present</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: has-pizza
  labels:
    pizza: is-great
spec:
  containers:
    - name: nginx
      image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredlabels/samples/verify-label-key-only/example_allowed.yaml
```

</details>
<details>
<summary>label-missing</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: does-not-have-pizza
  labels:
    taco: is-great
spec:
  containers:
    - name: nginx
      image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requiredlabels/samples/verify-label-key-only/example_disallowed.yaml
```

</details>


</details>