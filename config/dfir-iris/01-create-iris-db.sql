-- iriswebapp_db's own 10-create_user.sh runs `psql --username ${POSTGRES_USER}`
-- with no --dbname flag, so psql defaults the target database to the
-- username itself ("iris"), not POSTGRES_DB ("iris_db"). Since only
-- iris_db actually gets created, that connection fails with
-- "FATAL: database iris does not exist" before the script ever reaches
-- its CREATE USER statement, so iris_adm never gets created (upstream
-- bug in ghcr.io/dfir-iris/iriswebapp_db). This database is otherwise
-- unused - it only needs to exist so that initial connection succeeds.
CREATE DATABASE iris;

-- iris-app/iris-worker also open a connection to "iris_tasks" (their
-- Celery task-results backend) that iriswebapp_db never creates either.
CREATE DATABASE iris_tasks;
