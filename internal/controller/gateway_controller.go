package controller

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	edgev1alpha1 "github.com/edge-infra/control-plane/internal/controller/api/v1alpha1"
	"github.com/edge-infra/control-plane/internal/store"
)

const requeueOnError = 30 * time.Second

// GatewayReconciler reconciles edge.io/v1alpha1 Gateway CRs into the
// configuration store, then asks the xDS reconciler to push a new snapshot.
type GatewayReconciler struct {
	// Client is the controller-runtime client used to read/write CRs.
	Client client.Client
	// Scheme is the runtime scheme registered with the manager.
	Scheme *runtime.Scheme
	// Store persists the desired Gateway state.
	Store store.Store
	// Trigger requests an immediate xDS reconcile after a mutation.
	Trigger Trigger
}

// Reconcile implements reconcile.Reconciler.
func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx).WithValues("gateway", req.NamespacedName)

	var gw edgev1alpha1.Gateway
	if err := r.Client.Get(ctx, req.NamespacedName, &gw); err != nil {
		if apierrors.IsNotFound(err) {
			if derr := r.Store.DeleteGateway(ctx, req.Name); derr != nil {
				log.Error(derr, "delete gateway after CR not found")
				return ctrl.Result{RequeueAfter: requeueOnError}, derr
			}
			r.Trigger.TriggerNow()
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !gw.DeletionTimestamp.IsZero() {
		if err := r.Store.DeleteGateway(ctx, gw.Name); err != nil {
			log.Error(err, "delete gateway on deletion timestamp")
			return ctrl.Result{RequeueAfter: requeueOnError}, err
		}
		r.Trigger.TriggerNow()
		if controllerutil.RemoveFinalizer(&gw, edgev1alpha1.ControllerFinalizer) {
			if err := r.Client.Update(ctx, &gw); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if controllerutil.AddFinalizer(&gw, edgev1alpha1.ControllerFinalizer) {
		if err := r.Client.Update(ctx, &gw); err != nil {
			return ctrl.Result{}, err
		}
	}

	domain := store.Gateway{
		Name:         gatewayDomainName(gw),
		Port:         uint32(gw.Spec.Port),
		Protocol:     gw.Spec.Protocol,
		TLSSecret:    gw.Spec.TLSSecretName,
		NodeSelector: gw.Spec.NodeSelector,
	}
	if err := r.Store.UpsertGateway(ctx, domain); err != nil {
		log.Error(err, "upsert gateway")
		return r.markFailed(ctx, &gw, err)
	}
	r.Trigger.TriggerNow()

	patch := client.MergeFrom(gw.DeepCopy())
	gw.Status.Synced = true
	gw.Status.LastSyncedAt = metav1.Now()
	gw.Status.ConnectedProxies = 0
	if err := r.Client.Status().Patch(ctx, &gw, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch status: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *GatewayReconciler) markFailed(ctx context.Context, gw *edgev1alpha1.Gateway, cause error) (ctrl.Result, error) {
	patch := client.MergeFrom(gw.DeepCopy())
	gw.Status.Synced = false
	gw.Status.LastSyncedAt = metav1.Now()
	if perr := r.Client.Status().Patch(ctx, gw, patch); perr != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("%w (status patch: %v)", cause, perr)
	}
	return ctrl.Result{RequeueAfter: requeueOnError}, cause
}

// SetupWithManager wires this reconciler into the controller-runtime Manager.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&edgev1alpha1.Gateway{}).
		Complete(r)
}

func gatewayDomainName(gw edgev1alpha1.Gateway) string {
	if gw.Spec.Name != "" {
		return gw.Spec.Name
	}
	return gw.Name
}
