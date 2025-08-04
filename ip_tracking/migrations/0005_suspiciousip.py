# Generated manually for ip_tracking.SuspiciousIP

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('ip_tracking', '0003_requestlog_city_requestlog_country_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='SuspiciousIP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(help_text='Suspicious IP address (IPv4 or IPv6)')),
                ('reason', models.CharField(help_text='Reason for flagging this IP as suspicious', max_length=255)),
                ('detected_at', models.DateTimeField(default=django.utils.timezone.now, help_text='When the suspicious activity was detected')),
                ('request_count', models.PositiveIntegerField(default=0, help_text='Number of requests that triggered detection')),
                ('is_resolved', models.BooleanField(default=False, help_text='Whether this suspicious activity has been reviewed')),
                ('flagged_paths', models.JSONField(blank=True, default=list, help_text='List of suspicious paths accessed')),
            ],
            options={
                'verbose_name': 'Suspicious IP',
                'verbose_name_plural': 'Suspicious IPs',
                'db_table': 'ip_tracking_suspicious_ip',
                'ordering': ['-detected_at'],
            },
        ),
        migrations.AddIndex(
            model_name='suspiciousip',
            index=models.Index(fields=['ip_address'], name='ip_tracking_ip_address_idx'),
        ),
        migrations.AddIndex(
            model_name='suspiciousip',
            index=models.Index(fields=['detected_at'], name='ip_tracking_detected_at_idx'),
        ),
        migrations.AddIndex(
            model_name='suspiciousip',
            index=models.Index(fields=['is_resolved'], name='ip_tracking_is_resolved_idx'),
        ),
    ]
