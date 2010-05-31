package TestCanVisit::Controller::Root;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller::ActionRole' };

__PACKAGE__->config(namespace => q{});

sub index :Path Args(0) {
    my ($self, $c) = @_;
    $c->res->body('action: index');
}

sub access :Local {
    my ($self, $c) = @_;

    my $action_name = $c->req->params->{action_name};
    my $action = $c->dispatcher->get_action_by_path($action_name);
    my $rc = $action->can_visit($c, $self);

    $c->res->body($rc ? 'yes' : 'no');
}

sub edit
    :Local
    :Does('ACL')
    :AllowedRole(admin)
    :AllowedRole(editor)
    :ACLDetachTo(denied)
    { }
sub read
    :Local
    :Does('ACL')
    :RequiresRole(user)
    :ACLDetachTo(denied)
    { }

sub readMysteriously
    :Local
    :Does('ACL')
    :AuthzValidateMethod('evenName')
    :ACLDetachTo(denied)
    { }

sub readMysteriouslyAsAdmin
    :Local
    :Does('ACL')
    :AuthzValidateMethod('evenName')
    :RequiresRole(admin)
    :ACLDetachTo(denied)
    { }



sub onlyShortUserIDs
    :Local
    :Does('ACL')
    :AuthzValidateMethod(nameLength)
    :AuthzValidateArg(5)
    :AuthzValidateArg(11)
    :ACLDetachTo(denied)
    { }

sub denied :Private {
    my ($self, $c) = @_;

    $c->res->status(403);
    $c->res->body('access denied');
}


# An odd condition, which returns true under weird circumstances,
# here, where ord(first letter of userid) is even
sub evenName :Private{
    my( $self, $user, $c) =  @_;

    my $num = ord(substr($user->id,0,1));
    return 0 == $num %2;
}


use Data::Dumper;
# a parameterized condition, returns 
sub nameLength :Private{
    my ($self, $user, $c, $arg) = @_;
    die "undef $arg" unless $arg;
    my ($lowerBound, $upperBound) = @$arg;
    return ($lowerBound <= length($user->id)) 
	&& (length($user->id) <= $upperBound);
}



__PACKAGE__->meta->make_immutable;

