insert into minitwit.user (username, email, pw_hash, whom) values ('user1', 'jjsmith@gmail.com', 'sha1$Z9wtkQam$7e6e814998ab3de2b63401a58063c79d92865d79', ['user1','user2','user3']);
insert into minitwit.user (username, email, pw_hash, whom) values ('user2', 'tj@gmail.com', 'sha1$Z9wtkQam$7e6e814998ab3de2b63401a58063c79d92865d79', ['user2']);
insert into minitwit.user (username, email, pw_hash, whom) values ('user3', 'cr@gmail.com', 'sha1$Z9wtkQam$7e6e814998ab3de2b63401a58063c79d92865d79', ['user1','user3']);


insert into minitwit.message (username, email, text, pub_date) values ('user1', 'jjsmith@gmail.com', 'user1s first post', 1259147653.31);
insert into minitwit.message (username, email, text, pub_date) values ('user2', 'tj@gmail.com', 'user2s post', 1359147658.31);
insert into minitwit.message (username, email, text, pub_date) values ('user3', 'cr@gmail.com', 'user3s userrr3333', 1459147693.31);
