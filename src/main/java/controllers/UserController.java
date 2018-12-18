package controllers;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import model.User;
import org.apache.solr.common.util.Hash;
import utils.Hashing;
import utils.Log;

public class UserController {

  private static DatabaseController dbCon;

  public UserController() {
    dbCon = new DatabaseController();
  }

  public static User getUser(int id) {

    // Check for connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Build the query for DB
    String sql = "SELECT * FROM user where id=" + id;

    // Actually do the query
    ResultSet rs = dbCon.query(sql);
    User user = null;

    try {
      // Get first object, since we only have one
      if (rs.next()) {
        user =
            new User(
                rs.getInt("id"),
                rs.getString("first_name"),
                rs.getString("last_name"),
                rs.getString("password"),
                rs.getString("email"));

        // return the create object
        return user;
      } else {
        System.out.println("No user found");
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return null
    return user;
  }

  /**
   * Get all users in database
   *
   * @return
   */
  public static ArrayList<User> getUsers() {

    // Check for DB connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Build SQL
    String sql = "SELECT * FROM user";

    // Do the query and initialyze an empty list for use if we don't get results
    ResultSet rs = dbCon.query(sql);
    ArrayList<User> users = new ArrayList<User>();

    try {
      // Loop through DB Data
      while (rs.next()) {
        User user =
            new User(
                rs.getInt("id"),
                rs.getString("first_name"),
                rs.getString("last_name"),
                rs.getString("password"),
                rs.getString("email"));

        // Add element to list
        users.add(user);
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return the list of users
    return users;
  }

  public static Hashing hashing = new Hashing();

  public static User createUser(User user) {

    // Write in log that we've reach this step
    Log.writeLog(UserController.class.getName(), user, "Actually creating a user in DB", 0);

    // Set creation time for user.
    user.setCreatedTime(System.currentTimeMillis() / 1000L);

    // Check for DB Connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Insert the user in the DB
    // TODO: Hash the user password before saving it. (FIX)
    int userID = dbCon.insert(
        "INSERT INTO user(first_name, last_name, password, email, created_at) VALUES('"
            + user.getFirstname()
            + "', '"
            + user.getLastname()
            + "', '"
                //Hashing the user password by a SHA (Secure Hash Algorithm) so the password can't be reversed.
                //getPassword is also salted
            + hashing.saltingSha(user.getPassword())
            + "', '"
            + user.getEmail()
            + "', "
            + user.getCreatedTime()
            + ")");

    if (userID != 0) {
      //Update the userid of the user before returning
      user.setId(userID);
    } else{
      // Return null if user has not been inserted into database
      return null;
    }

    // Return user
    return user;
  }

  public static boolean updateUser(User user, String token) {

    DecodedJWT jwt = null;

    if (dbCon == null) {
      dbCon = new DatabaseController();
    }
    try {
      Algorithm algorithm = Algorithm.HMAC256("secret");
      JWTVerifier verifier = JWT.require(algorithm)
              .withIssuer("auth0")
              .build();
      jwt = verifier.verify(token);
    } catch (JWTCreationException e) {
      System.out.println(e.getMessage());
    }
    boolean succes = dbCon.update("UPDATE user SET first_name = '" + user.getFirstname()
            + "', last_name ='" + user.getLastname()
            + "', password ='" + hashing.saltingSha(user.getPassword())
            + "', email ='" + user.getEmail()
            + "' WHERE id ='" + jwt.getClaim("userid").asInt());
    {
      if (succes) {
        return true;
      } else {
        return false;
      }
    }
  }

  public static String loginUser(User user) {

    String token = null;
    User userlogin;
    // Check for DB Connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }
    String sql = "SELECT * FROM user where email=" + user.getEmail() + "'AND password='" + user.getPassword() + "'";

    dbCon.insert(sql);

    ResultSet rs = dbCon.query(sql);


    try {
      if (rs.next()) {
        userlogin =
                new User(
                        rs.getInt("id"),
                        rs.getString("first_name"),
                        rs.getString("last_name"),
                        rs.getString("password"),
                        rs.getString("email")
                        );

        if (userlogin != null) {
          try {
            Algorithm algorithm = Algorithm.HMAC256("secret");
            token = JWT.create()
                    .withClaim("userid", userlogin.getId())
                    .withIssuer("auth0")
                    .sign(algorithm);
          } catch (JWTCreationException e) {
            System.out.println(e.getMessage());
          } finally {
            return token;
          }
        }
      } else {
        System.out.println("User not found");
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }
  return null;
}
public static boolean deleteUser(String token) {

  DecodedJWT jwt = null;
  Log.writeLog(UserController.class.getName(), "", "Delete user", 0);

  if (dbCon == null) {
    dbCon = new DatabaseController();
  }
  try {
    Algorithm algorithm = Algorithm.HMAC256("secret");
    JWTVerifier verifier = JWT.require(algorithm)
            .withIssuer("auth0")
            .build();
    jwt = verifier.verify(token);
  } catch (JWTCreationException e) {
    System.out.println(e.getMessage());
  }
  boolean succes = dbCon.update("DELETE FROM user WHERE id=" + jwt.getClaim("userid"));
  {
    if (succes) {
      return true;
    } else {
      return false;
    }
  }
}
}