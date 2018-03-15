insert into user (user_id, username, email, pw_hash) values ('1', 'user1', 'jjsmith@gmail.com', 'sha1$Z9wtkQam$7e6e814998ab3de2b63401a58063c79d92865d79');
insert into user (user_id, username, email, pw_hash) values ('2', 'user2', 'tj@gmail.com', 'sha1$Z9wtkQam$7e6e814998ab3de2b63401a58063c79d92865d79');
insert into user (user_id, username, email, pw_hash) values ('3', 'user3', 'cr@gmail.com', 'sha1$Z9wtkQam$7e6e814998ab3de2b63401a58063c79d92865d79');

insert into follower (who_id, whom_id) values ('1', '2');

insert into message (author_id, text, pub_date) values ('1', 'SQL is great!', '1359147653.31');
insert into message (author_id, text, pub_date) values ('2', 'It is what it is...', '1359147653.31');
insert into message (author_id, text, pub_date) values ('3', 'Today is great!', '1359147653.31');
