from django.db import migrations, models


def keep_latest(apps, schema_editor):
    # Match the legacy redirect's .last() behavior before adding uniqueness.
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("DELETE FROM app_url WHERE id NOT IN (SELECT MAX(id) FROM app_url GROUP BY shortened)")


class Migration(migrations.Migration):
    dependencies = [("app", "0002_destination_length")]
    operations = [
        migrations.RunPython(keep_latest, migrations.RunPython.noop),
        migrations.AddConstraint(model_name="url", constraint=models.UniqueConstraint(fields=["shortened"], name="unique_short_name")),
    ]
