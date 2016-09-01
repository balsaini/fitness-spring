package com.chyld.entities;

import com.chyld.enums.GenderEnum;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "profiles")
@Data
public class Profile {
    private int id;
    private int version;
    private GenderEnum gender;
    private int age;
    private float height;
    private float weight;
    private String photo;
    private User user;
    private Date created;
    private Date modified;

    @Id
    @GeneratedValue
    public int getId() {return id;}
    public void setId(int id) {this.id = id;}

    @Version
    public int getVersion() {return version;}
    public void setVersion(int version) {this.version = version;}

    @Enumerated(EnumType.STRING)
    @Column(columnDefinition = "ENUM('M', 'F')")
    public GenderEnum getGender() {return gender;}
    public void setGender(GenderEnum gender) {this.gender = gender;}

    @OneToOne
    @JoinColumn(name="user_id")
    @JsonIgnore
    public User getUser() {return user;}
    public void setUser(User user) {this.user = user;}

    @CreationTimestamp
    public Date getCreated() {return created;}
    public void setCreated(Date created) {this.created = created;}

    @UpdateTimestamp
    public Date getModified() {return modified;}
    public void setModified(Date modified) {this.modified = modified;}
}
