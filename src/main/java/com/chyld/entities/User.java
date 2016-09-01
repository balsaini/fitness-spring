package com.chyld.entities;

import com.chyld.enums.RoleEnum;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import javax.persistence.CascadeType;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Entity
@Table(name = "users")
@Data
public class User implements UserDetails {
    private int id;
    private int version;
    private String username;
    private String password;
    private boolean enabled;
    private List<Role> roles;
    private Profile profile;
    private Date created;
    private Date modified;
    private int loginAttempts;

    @Id
    @GeneratedValue
    public int getId() {return id;}
    public void setId(int id) {this.id = id;}

    @Version
    public int getVersion() {return version;}
    public void setVersion(int version) {this.version = version;}

    @Column(nullable = false)
    public String getUsername() {return username;}
    public void setUsername(String username) {this.username = username;}

    @Column(nullable = false)
    @JsonIgnore
    public String getPassword() {return password;}
    public void setPassword(String password) {this.password = password;}

    @ManyToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinTable(name = "roles_users",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"))
    public List<Role> getRoles() {return roles;}
    public void setRoles(List<Role> roles) {this.roles = roles;}

    @Transient
    public boolean isAdmin() {
        for (Role role : getRoles()) {
            if (role.getRole() == RoleEnum.ADMIN) {
                return true;
            }
        }
        return false;
    }

    @OneToOne(cascade = CascadeType.ALL, mappedBy = "user")
    public Profile getProfile() {return profile;}
    public void setProfile(Profile profile) {this.profile = profile;}

    @CreationTimestamp
    public Date getCreated() {return created;}
    public void setCreated(Date created) {this.created = created;}

    @UpdateTimestamp
    public Date getModified() {return modified;}
    public void setModified(Date modified) {this.modified = modified;}

    @Column(nullable = false)
    public int getLoginAttempts() {
        return loginAttempts;
    }
    public void setLoginAttempts() {
        this.loginAttempts = this.loginAttempts + 1;
    }

    @Override
    @Transient
    public Collection<? extends GrantedAuthority> getAuthorities() {return this.getRoles();}

    @Override
    @Transient
    public boolean isAccountNonExpired() {return this.isEnabled();}

    @Override
    @Transient
    public boolean isAccountNonLocked() {return this.isEnabled();}

    @Override
    @Transient
    public boolean isCredentialsNonExpired() {return this.isEnabled();}

    @Override
    public boolean isEnabled() {return this.enabled;}
    public void setEnabled(boolean enabled) {this.enabled = enabled;}

}
