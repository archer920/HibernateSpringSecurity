package com.stonesoupprorgramming.hibernatelogin

import org.hibernate.SessionFactory
import org.hibernate.annotations.FetchMode
import org.hibernate.annotations.FetchProfile
import org.hibernate.annotations.FetchProfiles
import org.hibernate.criterion.Restrictions
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Controller
import org.springframework.stereotype.Repository
import org.springframework.stereotype.Service
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import javax.persistence.*
import javax.transaction.Transactional

@SpringBootApplication
class HibernateLoginApplication

@Entity
data class Roles(@field: Id @field: GeneratedValue var id : Int = 0,
                 @field: ManyToOne(targetEntity = SiteUser::class) var user : SiteUser,
                 var role: String = "")

@FetchProfiles(
        FetchProfile(name = "default",
                fetchOverrides = arrayOf(
                        FetchProfile.FetchOverride(entity = SiteUser::class, association = "roles", mode = FetchMode.JOIN)))
)
@Entity
data class SiteUser (@field: Id @field: GeneratedValue var id : Int = 0,
                     var userName: String = "",
                     var password: String = "",
                     var enabled : Boolean = true,
                     var accountNonExpired: Boolean = true,
                     var credentialsNonExpired: Boolean = true,
                     var accountNonLocked : Boolean = true,
                     @field: OneToMany(targetEntity = Roles::class) var roles: MutableSet<Roles> = mutableSetOf()){

    //Convert this class to Spring Security's User object
    fun toUser() : User {
        val authorities = mutableSetOf<GrantedAuthority>()
        roles.forEach { authorities.add(SimpleGrantedAuthority(it.role)) }
        return User(userName, password,enabled, accountNonExpired, credentialsNonExpired, accountNonLocked,authorities);
    }
}

@Configuration
class DataConfig {
    @Bean
    fun sessionFactory(@Autowired entityManagerFactory: EntityManagerFactory) :
            SessionFactory = entityManagerFactory.unwrap(SessionFactory::class.java)
}

@Configuration
class SecurityConfig(@Autowired private val userService : UserService) : //Inject UserService
        WebSecurityConfigurerAdapter() { //Extend WebSecurityConfigureAdaptor

    //Override this method to configure Authentication
    override fun configure(auth: AuthenticationManagerBuilder) {
        auth
                .userDetailsService(userService) //We pass our userService to userDetailsService
                .passwordEncoder(BCryptPasswordEncoder()) //Pass our Encryption Scheme also
    }

    override fun configure(http: HttpSecurity) {
        http.
                formLogin()
                    .and()
                .httpBasic()
                    .and()
                .authorizeRequests()
                    .antMatchers("/display").authenticated()
                    .anyRequest().permitAll()

    }
}

@Transactional //Have Spring Manage Database Transactions
@Service //Mark this class as a Service layer class
class UserService(@Autowired private val userRepository: UserRepository) //Inject UserRepository into this class
    : UserDetailsService { //To work with Spring Security, it needs to implement UserDetailsService

    //Load a user by user name and call our SiteUser.toUser() method
    override fun loadUserByUsername(userName: String): UserDetails  = userRepository.loadByUsername(userName).toUser()

    //Saves a new user into the datastore
    fun saveOrUpdate(user : SiteUser){
        //Encrypt their password first
        user.password = BCryptPasswordEncoder().encode(user.password)

        //Then save the user
        userRepository.saveOrUpdate(user)
    }

    //Return all users
    fun allUsers() = userRepository.allUsers()
}

@Repository
//Inject SessionFactory into this class
class UserRepository(@Autowired private val sessionFactory: SessionFactory){

    //Used to save new users into the datastore
    fun saveOrUpdate(user: SiteUser){
        sessionFactory.currentSession.saveOrUpdate(user)
    }

    //Query the database by user name and return a SiteUser that matches
    //the user name
    fun loadByUsername(userName: String) : SiteUser =
            sessionFactory.currentSession.createCriteria(SiteUser::class.java, "su")
                    .add(Restrictions.eq("su.userName", userName)).uniqueResult() as SiteUser

    //Return all Site Users from the database
    fun allUsers(profile : String = "default") : List<SiteUser> {
        val session = sessionFactory.currentSession
        session.enableFetchProfile(profile)
        return session.createCriteria(SiteUser::class.java).list() as List<SiteUser>
    }
}

@Controller
@RequestMapping("/register")
class RegisterController(@Autowired private val userService: UserService){

    @RequestMapping(method = arrayOf(RequestMethod.GET))
    fun doGet(model: Model) : String{
        model.addAttribute("user", SiteUser())
        return "register"
    }

    @RequestMapping(method = arrayOf(RequestMethod.POST))
    fun doPost(siteUser: SiteUser) : String{
        userService.saveOrUpdate(siteUser)
        return "redirect:/display"
    }
}

@Controller
@RequestMapping("/display")
class UserDisplay(@Autowired private val userService: UserService){

    @RequestMapping(method = arrayOf(RequestMethod.GET))
    fun doGet(model: Model) : String{
        model.addAttribute("users", userService.allUsers())
        return "display"
    }
}

fun main(args: Array<String>) {
    SpringApplication.run(HibernateLoginApplication::class.java, *args)
}
