Standard flow to pull and redeploy on your AWS instance:

1. SSH into your AWS instance
ssh -i your-key.pem ec2-user@<aws-ip>

2. Pull latest changes
cd /path/to/macbook_data   # wherever the repo lives on AWS
git pull origin main

3. Rebuild and redeploy the manager
docker compose build manager
docker compose up -d manager

4. Verify it's healthy
docker ps --filter name=attacklens-manager
curl -sk http://localhost:8080/health

---
If you're not sure where the repo is on the AWS instance:
find / -name "docker-compose.yml" -path "*/macbook_data/*" 2>/dev/null

If you get a merge conflict on pull:
git stash          # stash any local AWS-side changes
git pull origin main
git stash pop      # re-apply if needed

The rebuild is required because the Python source files are baked into the Docker image — git pull alone won't apply the new code until you docker compose build.
