# README #

Source code for a Web application to help the coding of CVEs.


### Setting Up 

#### Pre-requisites 

* Python 2.7.x
* Django 1.10
* django-autocomplete-light==3.2.10
* django-ckeditor==5.2.1
* six==1.10.0

Assuming you have `pip` and `python` installed and configured to your path, you can run the command below to install django, the auto complete app, and the ckeditor app:
```
pip install -r requirements.txt
```


The application can be run using the built-in development server:
`python manage.py runserver`


Once the code is run, you can visit the admin interface to make the coding on `http://localhost:8000/admin/coding/`.
Please notice that the database is currently empty, so you will not see any CVEs there.

### Adapting the code for your needs 

1. Update the `models.py` file to reflect the structure of the data collected in your reserach;
2. Run Django's database migration commands. The database migrations can be applied via:
```
python manage.py makemigrations
python manage.py migrate
python manage.py migrate --database=db_coding
```
(Notice that by design, I am keeping each application in a separate database -- i.e., db_catalog.sqlite3, instead of db.sqlite3)
3. Update the `admin.py` file to indicate which fields are read-only, which ones are modifiable and which ones you want auto complete features.


### Side-notes 

* Code is **old**! The django version is deprecated and not supported anymore.
* Code is **not** configurable. The admin interfaces depend on the configuration in `models.py` and `admin.py`. If your data has a different schema, you have to change mostly these files to reflect the structure of the data you are analyzing.
* Tutorials on Django 1.10: https://docs.djangoproject.com/en/1.10/intro/tutorial01/