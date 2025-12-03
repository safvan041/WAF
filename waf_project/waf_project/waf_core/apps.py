from django.apps import AppConfig


class WafCoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'waf_project.waf_core'
    verbose_name = 'WAF Core'

    def ready(self):
        """Import signal handlers when the app is ready."""
        import waf_project.waf_core.signals  # noqa
