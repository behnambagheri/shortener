from django.test import TestCase, override_settings
from .models import Url
from .domains import destination, approved_domains


@override_settings(APPROVED_DOMAINS=["bea.sh", "behnam.pro"], SHORTENER_URL="https://s.bea.sh")
class PolicyTests(TestCase):
    def test_domain_boundaries_and_credentials(self):
        self.assertEqual(destination("https://ip.bea.sh/a", ["bea.sh"]), "https://ip.bea.sh/a")
        for value in ["https://evilbea.sh/", "https://bea.sh.evil.example/", "https://bea.sh@evil.example/", "https://u:p@bea.sh/", "https://bea.sh\\@evil.example/", "javascript:alert(1)"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                destination(value, ["bea.sh"])
        with self.assertRaises(ValueError):
            approved_domains([])

    def test_create_redirect_and_collision(self):
        data = {"original": "https://ip.bea.sh/path?q=1", "shortened": "example"}
        response = self.client.post("/api/links", data, content_type="application/json")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["short_url"], "https://s.bea.sh/example")
        self.assertEqual(self.client.get("/example")["Location"], data["original"])
        self.assertEqual(self.client.post("/api/links", data, content_type="application/json").status_code, 409)
        self.assertEqual(Url.objects.count(), 1)

    def test_revalidate_existing_links(self):
        Url.objects.create(original="https://other.example/", shortened="old")
        self.assertEqual(self.client.get("/old").status_code, 403)
        self.assertEqual(self.client.get("/missing").status_code, 404)
        self.assertEqual(self.client.post("/api/links", {"original":"https://unapproved.example/"}, content_type="application/json").status_code, 400)

    def test_frontend_assets_and_config(self):
        response = self.client.get("/")
        self.assertContains(response, "Short links")
        self.assertContains(response, "/assets/app-")
        self.assertEqual(self.client.get("/api/config").json()["approved_domains"], ["bea.sh", "behnam.pro"])
