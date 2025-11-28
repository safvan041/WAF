"""
Management command to train ML models for WAF anomaly detection
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from waf_project.waf_core.models import Tenant, SecurityEvent
from waf_project.waf_ml.models import TrafficPattern, MLModel, AnomalyScore
from waf_project.waf_ml.ml_engine import FeatureExtractor, AnomalyDetector
import time


class Command(BaseCommand):
    help = 'Train ML anomaly detection models for tenants'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Train model for specific tenant (by domain)',
        )
        parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Number of days of historical data to use for training',
        )
        parser.add_argument(
            '--min-samples',
            type=int,
            default=100,
            help='Minimum number of samples required for training',
        )

    def handle(self, *args, **options):
        tenant_domain = options.get('tenant')
        days = options.get('days')
        min_samples = options.get('min_samples')

        if tenant_domain:
            # Train for specific tenant
            try:
                tenant = Tenant.objects.get(domain=tenant_domain)
                self.train_tenant_model(tenant, days, min_samples)
            except Tenant.DoesNotExist:
                self.stdout.write(self.style.ERROR(f'Tenant not found: {tenant_domain}'))
        else:
            # Train for all active tenants
            tenants = Tenant.objects.filter(is_active=True)
            self.stdout.write(f'Training models for {tenants.count()} tenants...')
            
            for tenant in tenants:
                self.train_tenant_model(tenant, days, min_samples)

    def train_tenant_model(self, tenant, days, min_samples):
        """Train anomaly detection model for a specific tenant"""
        self.stdout.write(f'\nTraining model for tenant: {tenant.name}')
        
        # Get legitimate traffic (non-blocked requests) from the past N days
        cutoff_date = timezone.now() - timedelta(days=days)
        
        # Get anomaly scores for legitimate traffic (not blocked, low anomaly score)
        legitimate_scores = AnomalyScore.objects.filter(
            tenant=tenant,
            timestamp__gte=cutoff_date,
            was_blocked=False,
            is_anomaly=False
        ).values('features')
        
        # If not enough anomaly scores, use all non-blocked security events
        if legitimate_scores.count() < min_samples:
            self.stdout.write(
                self.style.WARNING(
                    f'Not enough anomaly score data ({legitimate_scores.count()}), '
                    f'need at least {min_samples} samples'
                )
            )
            self.stdout.write('Skipping training for this tenant.')
            return
        
        # Extract features from legitimate traffic
        feature_list = [score['features'] for score in legitimate_scores]
        
        self.stdout.write(f'Collected {len(feature_list)} training samples')
        
        # Train the model
        detector = AnomalyDetector(contamination=0.1)
        
        start_time = time.time()
        training_metrics = detector.train(feature_list)
        
        if 'error' in training_metrics:
            self.stdout.write(self.style.ERROR(f'Training failed: {training_metrics["error"]}'))
            return
        
        # Serialize and save the model
        model_data = detector.serialize()
        
        # Increment version number
        latest_version = MLModel.objects.filter(
            tenant=tenant,
            model_type='anomaly_detector'
        ).order_by('-model_version').first()
        
        new_version = (latest_version.model_version + 1) if latest_version else 1
        
        # Deactivate old models
        MLModel.objects.filter(
            tenant=tenant,
            model_type='anomaly_detector',
            is_active=True
        ).update(is_active=False)
        
        # Save new model
        ml_model = MLModel.objects.create(
            tenant=tenant,
            model_type='anomaly_detector',
            model_version=new_version,
            model_data=model_data,
            accuracy_score=1.0 - training_metrics.get('anomaly_rate', 0.1),
            training_samples_count=training_metrics['training_samples'],
            training_duration_seconds=training_metrics['training_duration_seconds'],
            is_active=True,
            training_config={
                'contamination': 0.1,
                'training_window_days': days,
                'detected_anomalies': training_metrics.get('detected_anomalies_in_training', 0)
            }
        )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'✓ Model v{new_version} trained successfully!\n'
                f'  - Samples: {training_metrics["training_samples"]}\n'
                f'  - Duration: {training_metrics["training_duration_seconds"]:.2f}s\n'
                f'  - Anomaly rate: {training_metrics.get("anomaly_rate", 0):.2%}'
            )
        )
