package geno.oauth.server.security.basic;

import geno.oauth.server.models.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class UserDetailsImpl implements UserDetails {

    public UserDetailsImpl() {
    }

    public UserDetailsImpl(User user) {
        this.user = user;
    }

    private User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getGrantedAuthorities();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUserName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return user.getStatus();
    }

    @Override
    public boolean isAccountNonLocked() {
        return user.getStatus();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return user.getStatus();
    }

    @Override
    public boolean isEnabled() {
        return user.getStatus();
    }
}
