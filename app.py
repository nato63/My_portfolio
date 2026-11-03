import os
import hmac
import secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
)
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///portfolio.db"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "change-me-locally")

db = SQLAlchemy(app)


# ---------- Models ----------


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    tech = db.Column(db.String(200), nullable=False)
    github_url = db.Column(db.String(300))
    live_url = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def tech_list(self):
        return [t.strip() for t in self.tech.split(",") if t.strip()]

    def __repr__(self):
        return f"<Project {self.title}>"


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Message {self.id} from {self.name}>"


# ---------- Admin helpers ----------


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def check_csrf():
    sent = request.form.get("csrf", "")
    if not hmac.compare_digest(sent, session.get("csrf", "")):
        abort(400)


app.jinja_env.globals["csrf_token"] = csrf_token


# ---------- Public routes ----------


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/projects")
def projects():
    all_projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template("projects.html", projects=all_projects)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        body = request.form.get("body", "").strip()

        # Spam trap: real users never see or fill this hidden field
        if request.form.get("website"):
            return redirect(url_for("contact"))

        if not name or not email or not body:
            flash("Please fill in all fields.", "error")
            return render_template("contact.html", name=name, email=email, body=body)

        if "@" not in email or len(body) > 2000:
            flash("Please enter a valid email and a shorter message.", "error")
            return render_template("contact.html", name=name, email=email, body=body)

        db.session.add(Message(name=name, email=email, body=body))
        db.session.commit()
        flash("Thanks! Your message has been sent.", "success")
        return redirect(url_for("contact"))

    return render_template("contact.html")


# ---------- Admin routes ----------


@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if hmac.compare_digest(password, ADMIN_PASSWORD):
            session.clear()
            session["is_admin"] = True
            return redirect(url_for("admin"))
        flash("Wrong password.", "error")
    return render_template("login.html")


@app.route("/admin/logout", methods=["POST"])
@login_required
def logout():
    check_csrf()
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("home"))


@app.route("/admin")
@login_required
def admin():
    all_projects = Project.query.order_by(Project.created_at.desc()).all()
    all_messages = Message.query.order_by(Message.created_at.desc()).all()
    return render_template("admin.html", projects=all_projects, messages=all_messages)


@app.route("/admin/projects/add", methods=["POST"])
@login_required
def add_project():
    check_csrf()
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    tech = request.form.get("tech", "").strip()
    github_url = request.form.get("github_url", "").strip() or None
    live_url = request.form.get("live_url", "").strip() or None

    if not title or not description or not tech:
        flash("Title, description and tech are required.", "error")
        return redirect(url_for("admin"))

    for url in (github_url, live_url):
        if url and not url.startswith(("http://", "https://")):
            flash("Links must start with http:// or https://", "error")
            return redirect(url_for("admin"))

    db.session.add(
        Project(
            title=title,
            description=description,
            tech=tech,
            github_url=github_url,
            live_url=live_url,
        )
    )
    db.session.commit()
    flash("Project added.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/projects/<int:project_id>/delete", methods=["POST"])
@login_required
def delete_project(project_id):
    check_csrf()
    db.session.delete(db.get_or_404(Project, project_id))
    db.session.commit()
    flash("Project deleted.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/messages/<int:message_id>/delete", methods=["POST"])
@login_required
def delete_message(message_id):
    check_csrf()
    db.session.delete(db.get_or_404(Message, message_id))
    db.session.commit()
    flash("Message deleted.", "success")
    return redirect(url_for("admin"))


# ---------- CLI ----------


@app.cli.command("seed")
def seed():
    """Add sample projects: flask --app app seed"""
    if Project.query.count() > 0:
        print("Projects already exist, skipping.")
        return
    db.session.add_all(
        [
            Project(
                title="Sample Project One",
                description="Replace this with a short description of what the project does.",
                tech="Python, Flask, SQLite",
                github_url="https://github.com/your-username/project-one",
            ),
        ]
    )
    db.session.commit()
    print("Added sample projects.")


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
