// Hand-written DeepCopy methods for the v1alpha1 API types. Equivalent to
// the output of `controller-gen object`, but committed directly so the
// package builds without a code-generation step.

package v1alpha1

import "k8s.io/apimachinery/pkg/runtime"

// DeepCopyInto copies in into out.
func (in *GatewaySpec) DeepCopyInto(out *GatewaySpec) {
	*out = *in
	if in.NodeSelector != nil {
		out.NodeSelector = make(map[string]string, len(in.NodeSelector))
		for k, v := range in.NodeSelector {
			out.NodeSelector[k] = v
		}
	}
}

// DeepCopy returns a deep copy of the receiver.
func (in *GatewaySpec) DeepCopy() *GatewaySpec {
	if in == nil {
		return nil
	}
	out := new(GatewaySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies in into out.
func (in *GatewayStatus) DeepCopyInto(out *GatewayStatus) {
	*out = *in
	in.LastSyncedAt.DeepCopyInto(&out.LastSyncedAt)
}

// DeepCopy returns a deep copy of the receiver.
func (in *GatewayStatus) DeepCopy() *GatewayStatus {
	if in == nil {
		return nil
	}
	out := new(GatewayStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies in into out.
func (in *Gateway) DeepCopyInto(out *Gateway) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy returns a deep copy of the receiver.
func (in *Gateway) DeepCopy() *Gateway {
	if in == nil {
		return nil
	}
	out := new(Gateway)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *Gateway) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies in into out.
func (in *GatewayList) DeepCopyInto(out *GatewayList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		items := make([]Gateway, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&items[i])
		}
		out.Items = items
	}
}

// DeepCopy returns a deep copy of the receiver.
func (in *GatewayList) DeepCopy() *GatewayList {
	if in == nil {
		return nil
	}
	out := new(GatewayList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *GatewayList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies in into out.
func (in *RouteRuleSpec) DeepCopyInto(out *RouteRuleSpec) {
	*out = *in
	if in.Hostnames != nil {
		out.Hostnames = append([]string(nil), in.Hostnames...)
	}
}

// DeepCopy returns a deep copy of the receiver.
func (in *RouteRuleSpec) DeepCopy() *RouteRuleSpec {
	if in == nil {
		return nil
	}
	out := new(RouteRuleSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies in into out.
func (in *RouteRuleStatus) DeepCopyInto(out *RouteRuleStatus) {
	*out = *in
	in.LastSyncedAt.DeepCopyInto(&out.LastSyncedAt)
}

// DeepCopy returns a deep copy of the receiver.
func (in *RouteRuleStatus) DeepCopy() *RouteRuleStatus {
	if in == nil {
		return nil
	}
	out := new(RouteRuleStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies in into out.
func (in *RouteRule) DeepCopyInto(out *RouteRule) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy returns a deep copy of the receiver.
func (in *RouteRule) DeepCopy() *RouteRule {
	if in == nil {
		return nil
	}
	out := new(RouteRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *RouteRule) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies in into out.
func (in *RouteRuleList) DeepCopyInto(out *RouteRuleList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		items := make([]RouteRule, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&items[i])
		}
		out.Items = items
	}
}

// DeepCopy returns a deep copy of the receiver.
func (in *RouteRuleList) DeepCopy() *RouteRuleList {
	if in == nil {
		return nil
	}
	out := new(RouteRuleList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *RouteRuleList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
