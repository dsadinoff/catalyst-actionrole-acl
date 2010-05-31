package Catalyst::ActionRole::ACL;
use Moose::Role;
use namespace::autoclean;

use vars qw($VERSION);
$VERSION = '0.05_02'; # REMEMBER TO BUMP VERSION IN Action::Role::ACL ALSO!

=head1 NAME

Catalyst::ActionRole::ACL - User role-based authorization action class

=head1 SYNOPSIS

 package MyApp::Controller::Foo;
 use Moose;
 use namespace::autoclean;

 BEGIN { extends 'Catalyst::Controller::ActionRole' }

 sub foo
 :Local
 :Does(ACL)
 :RequiresRole(admin)
 :ACLDetachTo(denied)
 {
     my ($self, $c) = @_;
     ...
 }

 sub denied :Private {
     my ($self, $c) = @_;

     $c->res->status('403');
     $c->res->body('Denied!');
 }

=head1 DESCRIPTION

Provides a L<Catalyst reusable action role|Catalyst::Controller::ActionRole>
for user role-based authorization.
ACLs are applied via the assignment of attributes to
application action subroutines.

=head1 REQUIRED ATTRIBUTES

Failure to include the following required attributes will result in an exception
when the ACL::Role action's constructor is called.

=head2 ACLDetachTo

The name of an action to which the request should be detached if it is
determined that ACLs are not satisfied for this user and the resource he
is attempting to access.

=head2 RequiresRole, AllowedRole or AuthzValidateMethod

The action must include at least one of these attributes, otherwise the Role::ACL
constructor will throw an exception.

=head1 Processing of ACLs

One or more roles may be associated with an action.

User roles are fetched, if necessary, via the invocation of the context "user" object's "roles"
method.

Roles specified with the RequiresRole attribute are checked before roles
specified with the AllowedRole attribute.

The mandatory ACLDetachTo attribute specifies the name of the action to which
execution will detach on access violation.

ACLs may be applied to chained actions so that different roles are required or
allowed for each link in the chain (or no roles at all).

ACLDetachTo allows us to short-circuit traversal of an action chain as soon as
access is denied to one of the actions in the chain by its ACL.

=head2 Examples

 # this is an invalid action
 sub broken
 :Local
 :Does(ACL)
 {
     my ($self, $c) = @_;
     ...
 }

 This action will cause an exception because it's missing the ACLDetachTo attribute
 and has none of the RequiresRole, AllowedRole, nor AuthzValidateMethod attributes. A Role::ACL action
 must include at least one RequiresRole, AllowedRole or AuthzValidateMethod attribute.

 sub foo
 :Local
 :Does(ACL)
 :RequiresRole(admin)
 :ACLDetachTo(denied)
 {
     my ($self, $c) = @_;
     ...
 }

This action may only be executed by users with the 'admin' role.

 sub bar :Local
 :Does(ACL)
 :RequiresRole(admin)
 :AllowedRole(editor)
 :AllowedRole(writer)
 :ACLDetachTo(denied)
 {
     my ($self, $c) = @_;
     ...
 }

This action requires that the user has the 'admin' role and
either the 'editor' or 'writer' role (or both).

 sub easy :Local
 :Does(ACL)
 :AllowedRole(admin)
 :AllowedRole(user)
 :ACLDetachTo(denied)
 {
     my ($self, $c) = @_;
     ...
 }

Any user with either the 'admin' or 'user' role may execute this action.


 sub complex :Local
 :Does(ACL)
 :AuthzValidateMethod(complexValidate)
 :AuthzValidateArg(hello)
 :AuthzValidateArg(there)
 :ACLDetachTo(denied)
 {
     my ($self, $c) = @_;
     ...
 }
 
 sub complexValidate :Private
 {
     my ($self, $user, $c, $args) = @_;
     return userHasPaidDuesAndIsGenerallyTrustworthyThisTimeOfDay($user);
 } 

This setup demonstrates how the "complex" action is only executed if
the arbitrary "complexValidate" criterion is met.  Note that the User
implementation need not support the "roles" feature if they are not used.
In addition, an arbitrary string may be passed between parens after the method
name.



 sub complex2 :Local
 :Does(ACL)
 :AuthzValidateMethod(complexValidate)
 :AllowedRole(admin)
 :ACLDetachTo(denied)
 {
     my ($self, $c) = @_;
     ...
 }
 
 sub complexValidate :Private
 {
     my ($self, $user, $c) = @_;
     return userHasPaidDuesAndIsGenerallyTrustworthyThisTimeOfDay($user);
 } 

Here, complex2 is only executed if complexValidate returns true, AND the user
has the 'admin' role.



=head1 WRAPPED METHODS

=cut

=head2 C<BUILD( $args )>

Throws an exception if parameters are missing or invalid.

=cut

sub BUILD { }

after BUILD => sub {
    my $class = shift;
    my ($args) = @_;

    my $attr = $args->{attributes};

    unless (exists $attr->{RequiresRole} || exists $attr->{AllowedRole} || exists $attr->{AuthzValidateMethod}) {
        Catalyst::Exception->throw(
            "Action '$args->{reverse}' requires at least one  RequiresRole, AllowedRole, AuthzValidateMethod attribute");
    }
    unless (exists $attr->{ACLDetachTo} && $attr->{ACLDetachTo}) {
        Catalyst::Exception->throw(
            "Action '$args->{reverse}' requires the ACLDetachTo(<action>) attribute");
    }
};

=head2 C<execute( $controller, $c )>

Overrides &Catalyst::Action::execute.

In order for delegation to occur, the context 'user' object must exist (authenticated user) and
the C<can_visit> method must return a true value.

See L<Catalyst::Action|METHODS/action>

=cut

around execute => sub {
    my $orig = shift;
    my $self = shift;
    my ($controller, $c) = @_;

    if ($c->user) {
        if ($self->can_visit($c, $controller)) {
            return $self->$orig(@_);
        }
    }

    my $denied = $self->attributes->{ACLDetachTo}[0];

    $c->detach($denied);
};

=head2 C<can_visit( $c, $controller )>

Return true if the authenticated user can visit this action.

This method is useful for determining in advance if a user can execute
a given action.

=cut

sub can_visit {
    my ($self, $c, $controller) = @_;

    die "you must pass in controller to can_visit" unless $controller;

    my $user = $c->user;

    return unless $user;

    my $usingRoles = $user->supports('roles') && $user->can('roles');
    my ($required, $allowed, %user_has);
    if( $usingRoles ){
        %user_has = map {$_,1} $user->roles;

        $required = $self->attributes->{RequiresRole};
	$allowed = $self->attributes->{AllowedRole};
    }

    my $authzMethodAttr = $self->attributes->{AuthzValidateMethod};
    if( $authzMethodAttr ){
	my $authzMethod = $authzMethodAttr->[0];
	$controller->$authzMethod($user,$c, $self->attributes->{AuthzValidateArg} ) 
	    or return;

	return 1 unless $usingRoles;

	if( ! ($required || $allowed)){
	    return 1;
	}
    }
    if ($required && $allowed) {
        for my $role (@$required) {
            return unless $user_has{$role};
        }
        for my $role (@$allowed) {
            return 1 if $user_has{$role};
        }
        return;
    }
    elsif ($required) {
        for my $role (@$required) {
            return unless $user_has{$role};
        }
        return 1;
    }
    elsif ($allowed) {
        for my $role (@$allowed) {
            return 1 if $user_has{$role};
        }
        return;
    }

    return;
}

1;

=head1 AUTHOR

David P.C. Wollmann E<lt>converter42@gmail.comE<gt>

=head1 CONTRIBUTORS

Converted from an action class to an action role by Tomas Doran (t0m)

=head1 BUGS

This is new code. Find the bugs and report them, please.

=head1 COPYRIGHT & LICENSE

Copyright 2009 by David P.C. Wollmann

This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

