# remove git repo
rm -rf .git
del .git

# To remove tracked files that are now in .gitignore, do this:
git rm -r --cached .
git add .
git commit -m "Remove ignored files from repo"


# Clone the repository from the remote Git server
git clone https://github.com/minyugu/00scripts
# or using SSH:
git clone git@github.com:your-org/your-repo.git
# Create a new branch to work on
git checkout -b feature/test-change

# Commit and push your changes
git add .
git commit -m "Add new script for X"
git push -u origin feature/my-change


# To merge into main, you must do it explicitly
# 1. Switch to main
git checkout main
# 2. Pull latest changes (optional but recommended)
git pull
# 3. Merge your branch
git merge feature/my-change
# 4. Push the updated main branch
git push


# see remote
git remote -v
# see branch
git branch -a