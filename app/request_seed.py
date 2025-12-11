import requests


def request_seed(student_id: str, github_repo_url: str, api_url: str):
    """
    Request encrypted seed from instructor API.
    """

    # 1. Read your public key (keep PEM markers)
    with open("student_public.pem", "r", encoding="utf-8") as f:
        public_key = f.read().strip()

    # 2. Prepare payload
    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key,
    }

    print("Sending request to Instructor API...\n")
    print("Payload being sent:")
    print("- student_id     :", student_id)
    print("- github_repo_url:", github_repo_url)
    print("- public_key first line:",
          public_key.splitlines()[0] if public_key else "EMPTY")
    print()

    try:
        # 3. Send POST request (no trailing slash in URL)
        response = requests.post(api_url, json=payload, timeout=15)
    except Exception as e:
        print("Request failed before reaching server:", e)
        return

    # 4. Show HTTP status and raw response so we can see the real error
    print("HTTP status code:", response.status_code)

    try:
        data = response.json()
        print("Raw JSON response:", data)
    except ValueError:
        print("Response was not JSON. Body:")
        print(response.text)
        return

    # 5. Check status from API
    if data.get("status") != "success":
        print("\nInstructor API reported error. Read the message above.")
        return

    encrypted_seed = data["encrypted_seed"]

    # 6. Save encrypted seed to file
    with open("encrypted_seed.txt", "w", encoding="utf-8") as f:
        f.write(encrypted_seed)

    print("\nEncrypted seed saved to encrypted_seed.txt (do NOT commit this file).")


if __name__ == "__main__":
    STUDENT_ID = "22MH1A05G2"
    GITHUB_REPO_URL = "https://github.com/JityaBusi/totp_gpp1"
    API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"

    request_seed(STUDENT_ID, GITHUB_REPO_URL, API_URL)