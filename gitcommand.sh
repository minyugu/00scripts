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
#git clone git@github.com:your-org/your-repo.git
# Create a new branch to work on
git checkout -b feature/nps

# Commit and push your changes
git add .
git commit -m "Add new script for test"
git push -u origin feature/test-change


# To merge into main, you must do it explicitly
# 1. Switch to main
git checkout main
# 2. Pull latest changes (optional but recommended)
git pull
# 3. Merge your branch
git merge feature/test-change
# 4. Push the updated main branch
git push


# see remote
git remote -v
# see branch
git branch -a

# config
git config --list --show-origin
git config --global user.name "My Gu"
git config --global user.email mygu@omygu.com