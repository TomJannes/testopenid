'use strict';
/* eslint new-cap: 0*/
var ObjectId = require('mongodb').ObjectId;

exports.id = '001-create-user';

exports.up = function(done) {
  var coll = this.db.collection('users');
  coll.insert({
    _id: ObjectId('560d00da421db3b427f90310'),
    sub: '560d00da421db3b427f90309',
    firstname: 'firstname',
    lastname: 'lastname',
    email: 'test@test.be',
    username: 'test',
    createdAt: new Date(),
    updatedAt: new Date()
  }, done);
};

exports.down = function(done) {
  var coll = this.db.collection('user');
  coll.remove({_id: ObjectId('560d00da421db3b427f90310')}, done);
};
