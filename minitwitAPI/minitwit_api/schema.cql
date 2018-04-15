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
  who_id int,
  whom_id int,
  primary key(who_id)
);

drop table if exists miniwit.message;
create table minitwit.message (
  message_id int,
  author_id int,
  text text,
  pub_date float,
  primary key(message_id)
);
