import os, tempfile, unittest
from pathlib import Path
import app as campus_app

class CampusFixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = campus_app.DB_PATH
        self.old_upload = campus_app.UPLOAD_DIR
        campus_app.DB_PATH = os.path.join(self.temp.name, "test.db")
        campus_app.UPLOAD_DIR = os.path.join(self.temp.name, "uploads")
        os.makedirs(campus_app.UPLOAD_DIR, exist_ok=True)
        campus_app.app.config.update(TESTING=True, SECRET_KEY="test-secret-key-for-tests", WTF_CSRF_ENABLED=False)
        campus_app.init_db()
        self.client = campus_app.app.test_client()

    def tearDown(self):
        campus_app.DB_PATH = self.old_db
        campus_app.UPLOAD_DIR = self.old_upload
        self.temp.cleanup()

    def csrf(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as sess:
            return sess["csrf_token"]

    def test_home_page_loads(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_post_without_csrf_is_rejected(self):
        self.assertEqual(self.client.post("/login", data={"email":"nobody@example.com", "password":"bad"}).status_code, 400)

    def test_demo_admin_can_login(self):
        token = self.csrf("/login")
        response = self.client.post("/login", data={"csrf_token":token,"email":"admin@campus.local","password":"Admin@123"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Fault dashboard", response.data)

    def test_student_registration(self):
        token = self.csrf("/register")
        response = self.client.post("/register", data={"csrf_token":token,"name":"Test Student","email":"student@example.com","password":"StrongPass123"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with campus_app.db() as con:
            row = con.execute("SELECT role FROM users WHERE email=?", ("student@example.com",)).fetchone()
        self.assertEqual(row["role"], "student")

    def test_security_headers(self):
        response = self.client.get("/")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")

if __name__ == "__main__": unittest.main()
