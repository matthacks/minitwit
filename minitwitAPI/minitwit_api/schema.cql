drop keyspace if exists minitwit;
create keyspace minitwit with replication = {'class': 'SimpleStrategy', 'replication_factor': 3};

drop table if exists minitwit.user;
create table minitwit.user (
  username text,
  email text,
  pw_hash text,
  whom list<text>,
  primary key(username)
);

drop table if exists minitwit.message;
create table minitwit.message (
  username text,
  pub_date float,
  email text,
  text text,
  primary key(username, pub_date) 
) with clustering order by (pub_date desc);

