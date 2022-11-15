import uuid
import string

def uuid32(): return uuid.uuid4().hex
def uuid64(): return uuid.uuid4().hex + uuid.uuid4().hex


def unique_generator(cls, field, value):
    ''' Generate a value that is unique to to the `field` attribute of the table `cls` '''
    params = {field: value}
    o = cls.query.filter_by(**params).first()
    if (o): return unique_generator(cls, field, value)
    return value



def verify_user_contact_info(): pass