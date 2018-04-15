drop keyspace if exists minitwit;
create keyspace minitwit with replication = {'class': 'SimpleStrategy', 'replication_factor': 3};

drop table if exists minitwit.user;
create table minitwit.user (

  username text,
  email text,
  pw_hash text,
  primary key(username)
);

drop table if exists minitwit.follower;
create table minitwit.follower (
  who text,
  whom list<text>,
  primary key(who)
);

drop table if exists minitwit.message;
create table minitwit.message (
  message_id timeuuid,
  username text,
  email text,
  text text,
  pub_date timestamp,
  primary key(message_id)
);

drop table if exists minitwit.timelines;
create table minitwit.timelines (
username text,
message_id timeuuid,
pub_date timestamp,
primary key((username),pub_date, message_id));
