# Profiles

One values file per chart, for each way of running Talyvor Edge. Pass the file for a chart with
`-f deploy/profiles/<profile>/<chart>.yaml` on its `helm upgrade --install`, as
[the install guide](../../docs/install.md#choose-a-profile) does.

| Profile | For |
|---|---|
| `lite` | one node: one copy of each service |
| `ha` | production on two or more workers: more copies, spread across nodes and zones |
| `airgap` | `ha`, with every image pulled from your own registry ([air-gapped install](../../docs/air-gap.md)) |

`make kubeconform`, `make verify-image-pins` and `make verify-xds-mtls` render every chart with
every profile; `make kind-install-guide` installs `ha` on kind.
