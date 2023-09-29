# Docker

docker pull mariadb:latest

# Python

## Client

Prereq

Mac OS
```
brew install mariadb-connector-c
```

PIP

```
python3 -m pip install mariadb
python3 -m pip install mysql-connector-python

```

# SQL

## Create Table

```sql
CREATE TABLE animals (
     id MEDIUMINT NOT NULL AUTO_INCREMENT,
     name CHAR(30) NOT NULL,
     PRIMARY KEY (id)
 );
```

