DROP TABLE IF EXISTS `users`;

-- Create users table
{migration}

-- Populate with test data
INSERT INTO `users` (username, hash, salt) VALUES
("mei", X'aac846b3ef07dc88f417cc73775e32724580c17b2068c11b722e9dc6a220c0e8', X'37a82d20d2f53963b1ac7934e9fc9b80c5778bc51bd57ccb33543d2da0d25069'),
("foobar", X'615585bfbdd7c762174fff0b026881900c29828f504df7f87b213872b057b8dc', X'25c9fee3f2cf30e278aaf8b2b42f18a73dd39b77cfd08bedbe93d9ba3c90befa');
