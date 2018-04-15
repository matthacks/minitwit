insert into minitwit.user (username, email, pw_hash) values ('user1', 'jjsmith@gmail.com', 'sha1$Z9wtkQam$7e6e814998ab3de2b63401a58063c79d92865d79');
insert into minitwit.user (username, email, pw_hash) values ('user2', 'tj@gmail.com', 'sha1$Z9wtkQam$7e6e814998ab3de2b63401a58063c79d92865d79');
insert into minitwit.user (username, email, pw_hash) values ('user3', 'cr@gmail.com', 'sha1$Z9wtkQam$7e6e814998ab3de2b63401a58063c79d92865d79');

insert into minitwit.follower (who, whom) values ('user1', ['user2','user3']);
insert into minitwit.follower (who, whom) values ('user3', ['user1']);

insert into minitwit.message (message_id, username, email, text, pub_date) values (minTimeuuid('2014-10-12'), 'user1', 'jjsmith@gmail.com', 'user1s first post', '2011-5-02 12:10');
insert into minitwit.message (message_id, username, email, text, pub_date) values (minTimeuuid('2012-10-12'), 'user2', 'tj@gmail.com', 'user2s post', '2013-7-02 11:10');
insert into minitwit.message (message_id, username, email, text, pub_date) values (minTimeuuid('2013-10-12'), 'user3', 'cr@gmail.com', 'user3s userrr3333', '2015-2-02 07:10');

insert into minitwit.timelines (username, message_id, pub_date) values ('user3', minTimeuuid('2014-10-12'), '2011-5-02 12:10');
insert into minitwit.timelines (username, message_id, pub_date) values ('user1', minTimeuuid('2012-10-12'), '2013-7-02 11:10');
insert into minitwit.timelines (username, message_id, pub_date) values ('user1', minTimeuuid('2013-10-12'), '2015-2-02 07:10');
