DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS hostnames;
DROP TABLE IF EXISTS nsupdatekeys;

CREATE TABLE IF NOT EXISTS users (
    username VARCHAR PRIMARY KEY ,
    bcrypt VARCHAR
);

CREATE TABLE IF NOT EXISTS nsupdatekeys (
    keyid INTEGER PRIMARY KEY ASC,
    keyname VARCHAR,
    filename VARCHAR DEFAULT NULL,
    keydata VARCHAR DEFAULT NULL	
);

CREATE TABLE IF NOT EXISTS hostnames (
    hostname VARCHAR,
    username VARCHAR,
    keyid INTEGER,
    FOREIGN KEY (username) REFERENCES users (username),
    FOREIGN KEY (keyid) REFERENCES nsupdatekeys (keyid)
);

INSERT INTO users (username, bcrypt) VALUES
("heiko", "$2a$10$yh6yfkiLXFtyb1QboEqrE.TGjdkBsFdMrvRA8dq6WOdnseDIRdE8O"),
("buechse", "$2a$10$GgvwV9vKVqY.Ei.P8C.AP.kiw37BX8SogUu1a5PgjBXQGPuMq1pYe");

INSERT INTO nsupdatekeys (keyname, filename, keydata) VALUES
("heiko.dyn.bl0rg.net.", NULL, "94e166ac5c1acbb7d23928b87550a5808a773fcd84f8e716d1681bb3c0cee5453adeaf28dd5b44fdd121695bff403560f214c59decc78ce6b18eaa6046520c64"),
("buechse.dyn.bl0rg.net.", "/tmp/test.key", NULL);

INSERT INTO hostnames (hostname, username, keyid) VALUES
("sprawl.dyn.bl0rg.net", "heiko", 1),
("buechse.syn.bl0rg.net", "buechse", 2),
("buechse-priv.syn.bl0rg.net", "buechse", 2);
