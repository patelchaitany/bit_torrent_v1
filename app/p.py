from locust import HttpUser, task, between
import uuid
import random
import datetime

class BookUser(HttpUser):
    wait_time = between(0, 0)  # no wait, max load

    @task(1)  # 25% probability = read
    def read_books(self):
        self.client.get("api/book/get")

    @task(3)  # 75% probability = write + delete
    def write_and_delete_book(self):
        # Generate unique book data
        unique_id = str(uuid.uuid4())[:8]
        title = f"Book_{unique_id}"
        author = f"Author_{unique_id}"
        year = random.randint(1000, datetime.datetime.now().year)

        # Step 1: Create book
        create_resp = self.client.post(
            "api/book/add",   # <-- Adjust if your POST route differs
            json={"title": title, "author": author, "year": year}
        )

        # Step 2: Delete book (if created successfully)
        if create_resp.status_code in [200, 201]:
            book_id = create_resp.json().get("_id")
            if book_id:
                self.client.delete(f"api/book/delete/{book_id}")
