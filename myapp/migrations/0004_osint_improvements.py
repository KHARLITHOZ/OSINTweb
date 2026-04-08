from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('myapp', '0003_searchrecord_remove_task_project_ipresult_and_more'),
    ]

    operations = [
        # SearchRecord — FK de usuario + índices
        migrations.AddField(
            model_name='searchrecord',
            name='user',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='searches',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddIndex(
            model_name='searchrecord',
            index=models.Index(fields=['user', '-created_at'], name='myapp_searc_user_id_idx'),
        ),
        migrations.AddIndex(
            model_name='searchrecord',
            index=models.Index(fields=['-created_at'], name='myapp_searc_created_idx'),
        ),

        # IPResult — Reverse DNS (PTR)
        migrations.AddField(
            model_name='ipresult',
            name='reverse_dns',
            field=models.CharField(blank=True, max_length=255),
        ),

        # DomainResult — Subdominios crt.sh + SPF + DMARC
        migrations.AddField(
            model_name='domainresult',
            name='subdomains',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='domainresult',
            name='spf_record',
            field=models.CharField(blank=True, max_length=512),
        ),
        migrations.AddField(
            model_name='domainresult',
            name='dmarc_record',
            field=models.CharField(blank=True, max_length=512),
        ),
    ]
