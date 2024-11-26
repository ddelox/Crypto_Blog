from flask_ckeditor import CKEditorField
from flask_wtf import FlaskForm
from wtforms.fields.simple import StringField, SubmitField
from wtforms.validators import DataRequired
from sqlalchemy import Integer, String

class AddForm(FlaskForm):
    title = StringField(label="Title", validators=[DataRequired()])
    subtitle = StringField(label="Subtitle")
    author = StringField(label="Author")
    date = StringField(label="Date")
    img_url = StringField(label="Image URL")
    body = CKEditorField(label="Body", validators=[DataRequired()])
    submit = SubmitField('Submit Post')

