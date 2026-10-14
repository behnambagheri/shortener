from django.db import models


class Url(models.Model):
    original = models.CharField(max_length=2048)
    shortened = models.CharField(max_length=511)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["shortened"], name="unique_short_name")]
