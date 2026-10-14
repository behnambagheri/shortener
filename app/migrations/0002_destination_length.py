from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("app", "0001_initial")]
    operations = [migrations.AlterField(model_name="url", name="original", field=models.CharField(max_length=2048))]
