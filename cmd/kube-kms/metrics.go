package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	encryptTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kube_kms_encrypt_requests_total",
		Help: "Total KMS encrypt requests.",
	}, []string{"result"})

	encryptDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "kube_kms_encrypt_duration_seconds",
		Help:    "Latency of KMS encrypt requests.",
		Buckets: prometheus.DefBuckets,
	})

	decryptTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kube_kms_decrypt_requests_total",
		Help: "Total KMS decrypt requests.",
	}, []string{"result"})

	decryptDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "kube_kms_decrypt_duration_seconds",
		Help:    "Latency of KMS decrypt requests.",
		Buckets: prometheus.DefBuckets,
	})

	signTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kube_kms_sign_requests_total",
		Help: "Total JWT sign requests.",
	}, []string{"result"})

	signDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "kube_kms_sign_duration_seconds",
		Help:    "Latency of JWT sign requests.",
		Buckets: prometheus.DefBuckets,
	})

	fetchKeysTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kube_kms_fetch_keys_requests_total",
		Help: "Total FetchKeys requests.",
	}, []string{"result"})

	keyCacheRefreshTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kube_kms_key_cache_refreshes_total",
		Help: "Total JWT key cache refreshes (GCP round-trips).",
	}, []string{"result"})
)
