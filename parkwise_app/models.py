from django.db import models

class Bay(models.Model):
    number = models.CharField(max_length=10)
    available = models.BooleanField(default=True)
    def __str__(self):
        return f"Bay {self.number} - {'Available' if self.available else 'Occupied'}"

# Create your models here.
