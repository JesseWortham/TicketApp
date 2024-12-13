const { decodeBase64 } = require("bcryptjs");
const mysql = require("mysql");
const jwt = require('jsonwebtoken');
const bcrypt =require('bcryptjs');
const{promisify} =require('util');
const { appendFile } = require("fs");
const { debugPort } = require("process");
const { getPriority } = require("os");
const handlebarsHelpers = require('handlebars-helpers')();


const passport = require('passport');



const db= mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE
});


let connection = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE
});


const hbs = require('hbs');

// Priority Dropdown Helper
hbs.registerHelper('priorityDropdown', (selectedPriority) => {
  const priorities = ['Low', 'Medium', 'High']; // Modify this list as needed
  let options = '';

  priorities.forEach((priority) => {
    if (priority === selectedPriority) {
      options += `<option value="${priority}" selected>${priority}</option>`;
    } else {
      options += `<option value="${priority}">${priority}</option>`;
    }
  });

  return `<select name="priority">${options}</select>`;
});

// Format Date Helper
const formatDate = (date) => {
  if (!date) return "N/A"; // Handle empty date
  const parsedDate = new Date(date);
  if (isNaN(parsedDate.getTime())) return "Invalid Date"; // Handle invalid date
  
  const options = {
    hour: 'numeric',
    minute: 'numeric',
    second: 'numeric',
    timeZone: 'America/Chicago',
    timeZoneName: 'short',
  };
  return parsedDate.toLocaleString(undefined, options);
};

hbs.registerHelper('formatDate', formatDate);




exports.form = (req, res) => {
  res.render('add-user');
}

exports.hasRole = (role) => {
  return (req, res, next) => {
    // Assuming the user object is available on `req.user`
    if (req.user && req.user.role === role) {
      next(); // User has the required role, proceed to the next middleware/controller
    } else {
      res.status(403).send('Forbidden'); // User does not have the required role, send a forbidden error
    }
  };
};




exports.isAuthenticated = (req, res, next) => {

  console.log('isAuthenticated middleware');
  console.log(req.user); 
  // Check if the user is authenticated
  if (req.isAuthenticated()) {
    // User is authenticated, proceed to the next middleware or route handler
    return next();
  }

  // User is not authenticated, redirect to the login page or send an error response
  res.redirect('/login'); // Replace '/login' with your desired login page URL
};



exports.isAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next(); // User is an admin, proceed to the next middleware or route handler
  } else {
    res.status(403).send('Forbidden'); // User is not an admin, return a 403 Forbidden status
  }
};

exports.isUser = (req, res, next) => {
  if (req.user && req.user.role === 'user') {
    next(); // User is a regular user, proceed to the next middleware or route handler
  } else {
    res.status(403).send('Forbidden'); // User is not a regular user, return a 403 Forbidden status
  }
};


exports.searchdes = (req, res) => {
  const searchTerm = req.query.description;  // Get the search term from the query
  const userName = req.user.name;  // Get the logged-in user's name
  const userRole = req.user.role;  // Get the logged-in user's role

  // Base query to search for tickets by description
  let query = 'SELECT * FROM tickets WHERE description LIKE ?';
  let queryParams = [`%${searchTerm}%`];

  // Restrict results for regular users
  if (userRole !== 'admin') {
    query += ' AND assigned_to = ?';  // Filter tickets by assigned_to field
    queryParams.push(userName);  // Add the user's name to the query parameters
  }

  // Log the query and parameters for debugging
  console.log('Search Term:', searchTerm);
  console.log('User Name:', userName);
  console.log('User Role:', userRole);
  console.log('Final Query:', query);
  console.log('Query Params:', queryParams);

  // Execute the query
  connection.query(query, queryParams, (err, rows) => {
    if (err) {
      console.error('Error executing query:', err);
      return res.status(500).send('Database error');
    }

    console.log('Query Results:', rows);
    res.render('search-results', { results: rows });
  });
};





/*exports.update = (req, res) => {
  const { name, description, priority } = req.body;
  // User the connection
  connection.query('UPDATE tickets SET name = ? , description = ?, priority = ? WHERE id = ?', [name, description, priority,  req.params.id], (err, rows) => {

    if (!err) {
      // User the connection
      connection.query('SELECT * FROM tickets WHERE id = ?', [req.params.id], (err, rows) => {
        // When done with the connection, release it
        
        if (!err) {
          res.render('edit-ticket', { rows, alert: `${name} has been updated.` });
        } else {
          console.log(err);
        }
        console.log('The data from tickets table: \n', rows);
      });
    } else {
      console.log(err);
    }
    console.log('The data from tickets table: \n', rows);
  });
};*/





exports.edit = (req, res) => {
  const ticketId = req.params.id;
  const loggedInUserId = req.user.id; // Get logged-in user's ID

  if (req.method === 'POST') {
    // Extract data from the form submission
    const { name, description, priority, assigned_user_id, assigned_to } = req.body;

    // Update the ticket in the database
    connection.query(
      'UPDATE tickets SET name = ?, description = ?, priority = ?, assigned_user_id = ?, assigned_to = ? WHERE id = ?',
      [name, description, priority, assigned_user_id, assigned_to, ticketId],
      (err) => {
        if (err) {
          console.error('Error updating ticket:', err);
          return res.status(500).send('Internal Server Error');
        }

        // Redirect to the edit page with a success message
        return res.redirect(`/edit-ticket/${ticketId}?updated=true`);
      }
    );
  } else {
    // Fetch the current ticket details
    connection.query('SELECT * FROM tickets WHERE id = ?', [ticketId], (err, ticketRows) => {
      if (err) {
        console.error('Error fetching ticket:', err);
        return res.status(500).send('Internal Server Error');
      }

      if (ticketRows.length === 0) {
        return res.status(404).send('Ticket not found');
      }

      const ticket = ticketRows[0];

      // Fetch the list of users from the database
      connection.query('SELECT id, name FROM users', (userErr, users) => {
        if (userErr) {
          console.error('Error fetching users:', userErr);
          return res.status(500).send('Internal Server Error');
        }

        // Fetch comments associated with the ticket
        connection.query('SELECT * FROM comments WHERE ticket_id = ?', [ticketId], (commentErr, commentRows) => {
          if (commentErr) {
            console.error('Error fetching comments:', commentErr);
            return res.status(500).send('Internal Server Error');
          }

          // Default to the creator if no assignee is set
          const currentAssigneeId = ticket.assigned_user_id || loggedInUserId;

          // Render the 'edit-ticket' page with ticket, users, comments, and a success message if updated
          const successMessage = req.query.updated === 'true' ? 'Ticket updated successfully!' : null;

          res.render('edit-ticket', {
            ticket,
            users,
            loggedInUserId,
            currentAssigneeId,
            comments: commentRows,
            successMessage // Set the success message based on query parameter
          });
        });
      });
    });
  }
};








// Add a route or endpoint for handling comment submissions
exports.submitComment = (req, res) => {
  const { ticketId, userId, userName, comment } = req.body;
  const timestamp = new Date().toISOString();

  // Execute SQL query to insert comment into the database
  connection.query('INSERT INTO comments (ticket_id, user_id, user_name, comment, timestamp) VALUES (?, ?, ?, ?, ?)',
    [ticketId, userId, userName, comment, timestamp],
    (error, results) => {
      if (error) {
        console.error('Error inserting comment:', error);
        return res.status(500).json({ error: 'An error occurred while inserting the comment' });
      }
      // Assuming successful insertion
      return res.status(200).json({ message: 'Comment inserted successfully' });
    });
};


exports.deleteUser = (req, res) => {
  const userIdToDelete = req.params.id;

  connection.query('DELETE FROM users WHERE id = ?', [userIdToDelete], (err, result) => {
    if (err) {
      console.error('Error deleting user:', err);
      return res.status(500).json({ error: 'Error deleting user' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({ message: 'User deleted successfully' });
  });
};


exports.updateTicket = (req, res) => {
  const ticketId = req.params.id;
  const { name, priority, description, assigned_user_id, assigned_to, comment } = req.body;
  const userId = req.user.id; // Assuming user ID is available after authentication
  const userName = req.user.name; // Assuming user name is available after authentication

  // Validate required fields
  if (!name || !priority || !description || !assigned_user_id || !assigned_to) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }

  // Start a transaction
  connection.beginTransaction(err => {
    if (err) {
      console.error('Error starting transaction:', err);
      return res.status(500).json({ error: 'An error occurred while starting the transaction' });
    }

    // Update the ticket
    connection.query(
      'UPDATE tickets SET name = ?, priority = ?, description = ?, assigned_user_id = ?, assigned_to = ? WHERE id = ?',
      [name, priority, description, assigned_user_id, assigned_to, ticketId],
      (updateErr, result) => {
        if (updateErr) {
          console.error('Error updating ticket:', updateErr);
          return connection.rollback(() => {
            res.status(500).json({ error: 'An error occurred while updating the ticket' });
          });
        }

        if (result.affectedRows === 0) {
          console.log('Ticket not found or update failed');
          return connection.rollback(() => {
            res.status(404).json({ error: 'Ticket not found or update failed' });
          });
        }

        // Insert comment if provided
        const insertComment = (callback) => {
          if (comment && comment.trim() !== '') {
            connection.query(
              'INSERT INTO comments (ticket_id, user_id, user_name, comment) VALUES (?, ?, ?, ?)',
              [ticketId, userId, userName, comment],
              (commentErr) => {
                if (commentErr) {
                  console.error('Error inserting comment:', commentErr);
                  return connection.rollback(() => {
                    res.status(500).json({ error: 'An error occurred while inserting the comment' });
                  });
                }
                callback(); // Continue to commit after comment insertion
              }
            );
          } else {
            callback(); // No comment to insert, proceed to commit
          }
        };

        // Commit the transaction
        insertComment(() => {
          connection.commit(commitErr => {
            if (commitErr) {
              console.error('Error committing transaction:', commitErr);
              return connection.rollback(() => {
                res.status(500).json({ error: 'An error occurred while committing the transaction' });
              });
            }

            // Success: Redirect with success message
            res.redirect(`/auth/edit-ticket/${ticketId}?updated=true`);
          });
        });
      }
    );
  });
};










// controllers/auth.js
exports.getTicketDetails = (req, res) => {
  const ticketId = req.params.id;
  
  // Perform the query to fetch the ticket details based on the ticketId
  connection.query('SELECT * FROM tickets WHERE id = ?', [ticketId], (err, rows) => {
    if (!err) {
      // If ticket with given ID is found in the database
      if (rows.length > 0) {
        const ticket = rows[0];
        
        // Perform another query to fetch comments along with user information
        connection.query('SELECT comments.*, users.name AS user_name FROM comments JOIN users ON comments.user_id = users.id WHERE comments.ticket_id = ?', [ticketId], (commentErr, comments) => {
          if (!commentErr) {
            // Log the comments array
            console.log('Comments:', comments);
            
            // Pass both ticket and comments data to the template
            res.render('ticket-details', { ticket, comments });
          } else {
            console.error('Error fetching comments:', commentErr);
            res.status(500).send('Internal Server Error');
          }
        });
      } else {
        // If ticket with given ID is not found, you can handle the error or redirect to a different page
        res.status(404).send('Ticket not found');
      }
    } else {
      console.error(err);
      // Handle the error as per your requirement
      res.status(500).send('Internal Server Error');
    }
  });
};
exports.updateUser = (req, res) => {
  const { id } = req.params;
  const { name, email, role } = req.body;

  connection.query(
    'UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?',
    [name, email, role, id],
    (err, result) => {
      if (err) {
        console.error('Error updating user:', err);
        return res.status(500).send('Internal Server Error');
      }
      // Redirect with a query parameter for success
      res.redirect('/user-settings?success=true');
    }
  );
};



// In authController.js




exports.submitticket = (req, res) => {
  const { name, priority, description } = req.body;
  const createdAt = new Date(); // Current date and time
  const assignedTo = req.user.name; // Assuming the user object has the 'id' property for the user who made the ticket

  db.query(
    'INSERT INTO tickets SET ?',
    { name: name, description: description, priority: priority, created_at: createdAt, assigned_to: assignedTo },
    (error, results) => {
      if (error) {
        // Handle the query error
        console.error('Error submitting ticket:', error);
        res.status(500).send('Error submitting ticket');
      } else {
        // Ticket submitted successfully, redirect to the "SubmitTicket" page with a success query parameter
        res.redirect('/SubmitTicket?success=true');
      }
    }
  );
};

exports.getAllTickets = (user, callback) => {
  // Define a SQL query based on the user's role
  let query = 'SELECT * FROM tickets WHERE status = "active"';

  if (user && user.role === 'admin') {
    // If the user is an admin, fetch all active tickets
    query = 'SELECT * FROM tickets WHERE status = "active"';
  } else if (user && user.role === 'user') {
    // If the user is a regular user, fetch only their own tickets
    query = 'SELECT * FROM tickets WHERE status = "active" AND assigned_to = ?';
  }

  // Execute the query
  db.query(query, [user ? user.name : null], (err, results) => {
    if (err) {
      console.error('Error fetching tickets:', err);
      return callback(err, null);
    }
    
    // Fetch comments for each ticket
    const ticketIds = results.map(ticket => ticket.id);
    const commentQuery = 'SELECT * FROM comments WHERE ticket_id IN (?)';
    db.query(commentQuery, [ticketIds], (commentErr, comments) => {
      if (commentErr) {
        console.error('Error fetching comments:', commentErr);
        return callback(commentErr, null);
      }
      
      // Combine ticket data with their respective comments
      const ticketsWithComments = results.map(ticket => {
        const ticketComments = comments.filter(comment => comment.ticket_id === ticket.id);
        return { ...ticket, comments: ticketComments };
      });
      
      callback(null, ticketsWithComments);
    });
  });
};



exports.viewRecentlyClosed = (req, res) => {
  // Fetch recently closed tickets from the database
  connection.query('SELECT * FROM tickets WHERE status = "closed"', (err, rows) => {
    if (!err) {
      res.render('recentlyClosedTickets', { rows });
    } else {
      console.log(err);
      // Handle the error, perhaps by rendering an error page
      res.status(500).send('Internal Server Error');
    }
  });
};


exports.recentlyClosedTickets = (req, res) => {
  const user = req.user; // Get the current user from the request

  // Query to fetch recently closed tickets assigned to the current user
  const query = 'SELECT * FROM tickets WHERE ticket_state = "closed" AND assigned_to = ?';

  // Execute the query
  db.query(query, [user ? user.name : null], (error, rows) => {
    if (error) {
      console.error('Error fetching recently closed tickets:', error);
      return res.status(500).json({ error: 'Failed to fetch recently closed tickets' });
    }

    // Log the states of the tickets to ensure they are correct
    console.log('Ticket States:', rows.map(ticket => ticket.ticket_state));

    // Format the closed_at date for each ticket
    rows.forEach(ticket => {
      if (ticket.closed_at) {
        const parsedDate = new Date(ticket.closed_at);
        const options = {
          hour: 'numeric',
          minute: 'numeric',
          second: 'numeric',
          timeZone: 'America/Chicago',
          timeZoneName: 'short',
        };
        ticket.formattedClosedAt = parsedDate.toLocaleString(undefined, options);
      } else {
        ticket.formattedClosedAt = "N/A";
      }
    });

    // Render the "Recently Closed Tickets" page with the filtered tickets
    res.render('recentlyClosedTickets', { rows });
  });
};





exports.viewopen = (req, res) => {
  console.log(req.user); // Log the user object to the console
  console.log(req.user.role); // Log the user's role to the console

  // Function to fetch comments for a given ticket ID
  const fetchComments = (ticketId) => {
    return new Promise((resolve, reject) => {
      connection.query('SELECT * FROM comments WHERE ticket_id = ?', [ticketId], (err, comments) => {
        if (err) {
          console.error('Error fetching comments for ticket:', ticketId, err);
          reject(err);
        } else {
          resolve(comments);
        }
      });
    });
  };

  // Check if the user is an admin
  if (req.user && req.user.role === 'admin') {
    // If the user is an admin, fetch all open tickets
    connection.query('SELECT * FROM tickets WHERE ticket_state = "open"', async (err, rows) => {
      if (!err) {
        // Fetch comments for each ticket
        for (const ticket of rows) {
          ticket.comments = await fetchComments(ticket.id);
        }
        let removedUser = req.query.removed;
        res.render('opentickets', { rows, removedUser });
      } else {
        console.log(err);
      }
      console.log('The data from profile table: \n', rows);
    });
  } else {
    // If the user is not an admin, fetch all open tickets assigned to the user
    connection.query('SELECT * FROM tickets WHERE ticket_state = "open" AND assigned_to = ?', [req.user.name], async (err, rows) => {
      if (!err) {
        // Fetch comments for each ticket
        for (const ticket of rows) {
          ticket.comments = await fetchComments(ticket.id);
        }
        let removedUser = req.query.removed;
        res.render('opentickets', { rows, removedUser });
      } else {
        console.log(err);
      }
      console.log('The data from profile table: \n', rows);
    });
  }
};



exports.updateTicketState = (req, res) => {
  const ticketId = req.body.ticketId;
  const newState = req.body.newState;

  let updateFields = {
    ticket_state: newState
  };

  if (newState === 'closed') {
    updateFields.closed_at = new Date(); // Set current timestamp when closing
  } else if (newState === 'open') {
    updateFields.closed_at = null; // Clear closed_at when opening
  }

  connection.query('UPDATE tickets SET ? WHERE id = ?', [updateFields, ticketId], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ message: 'Ticket state updated successfully.' });
  });
};








exports.openTickets = (req, res, next, user) => {
  const sortingOptions = ['severity', 'date', 'assignedTo'];
  const defaultSort = 'severity'; // Set a default sorting option

  let { sortBy, order } = req.query;
  if (!sortingOptions.includes(sortBy)) {
    // Invalid sortBy parameter, use the default sorting option
    sortBy = defaultSort;
  }

  if (req.method === 'POST') {
    // Handle adding comments to tickets
    const { ticketId, comment } = req.body;
    // Implement logic to add the comment to the database associated with the ticketId
    // For example:
    const commentData = {
      ticket_id: ticketId,
      comment: comment,
      commenter_name: user.name, // Assuming 'user' contains information about the currently logged-in user
      created_at: new Date() // Add the current timestamp
    };
    db.query('INSERT INTO comments SET ?', commentData, (error, result) => {
      if (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to add comment' });
      } else {
        res.status(200).json({ message: 'Comment added successfully' });
      }
    });
  } else {
    // Fetch open tickets and their associated comments from the database
    const query = `
      SELECT t.id, t.description, t.priority, t.created_at, t.assigned_to, t.ticket_state, c.comment
      FROM tickets t
      LEFT JOIN comments c ON t.id = c.ticket_id
      WHERE t.ticket_state = 'open'
    `;
    db.query(query, (error, rows) => {
      if (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch open tickets' });
      } else {
        // Group the rows by ticket ID to collect all comments for each ticket
        const ticketMap = {};
        rows.forEach(row => {
          const { id, description, priority, created_at, assigned_to, ticket_state, comment } = row;
          if (!ticketMap[id]) {
            ticketMap[id] = {
              id,
              description,
              priority,
              created_at,
              assigned_to,
              ticket_state,
              comments: [] // Initialize an array to store comments for this ticket
            };
          }
          // Add the comment to the comments array of the corresponding ticket
          if (comment) {
            ticketMap[id].comments.push(comment);
          }
        });

        // Extract the values from the ticketMap object to get an array of tickets with comments
        const sortedTickets = Object.values(ticketMap);

        // Sort open tickets based on the selected sorting option
        switch (sortBy) {
          case 'severity':
            sortedTickets.sort((a, b) => a.ticket_state.localeCompare(b.ticket_state));
            break;
          case 'date':
            sortedTickets.sort((a, b) => {
              const dateA = new Date(a.created_at);
              const dateB = new Date(b.created_at);
              return order === 'asc' ? dateA - dateB : dateB - dateA;
            });
            break;
          case 'assignedTo':
            sortedTickets.sort((a, b) => a.assigned_to.localeCompare(b.assigned_to));
            break;
          default:
            // Use the default sorting option
            sortedTickets.sort((a, b) => a.ticket_state.localeCompare(b.ticket_state));
        }

        // Render the list of sorted open tickets
        res.render('open-tickets', { user, sortBy, sortedTickets, order });
      }
    });
  }
};






exports.getTicketWithComments = (req, res, next) => {
  const ticketId = req.params.ticketId;

  // Fetch ticket details
  db.query('SELECT * FROM tickets WHERE id = ?', [ticketId], (error, ticketResult) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'Failed to fetch ticket details' });
    }

    const ticket = ticketResult[0]; // Assuming only one ticket is returned

    // Fetch comments associated with the ticket
    db.query('SELECT * FROM comments WHERE ticket_id = ?', [ticketId], (error, commentResult) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ error: 'Failed to fetch comments' });
      }

      const comments = commentResult;

      // Render the view with ticket details and comments
      res.render('ticket-details', { ticket, comments });
    });
  });
};






exports.getCountOfOpenTickets = (req, res, next) => {
  const user = req.user;

  // Query to fetch the count of open tickets assigned to the current user
  const query = 'SELECT COUNT(*) as ticketCount FROM tickets WHERE ticket_state = "open" AND assigned_to = ?';

  // Execute the query
  connection.query(query, [user ? user.name : null], (err, results) => {
    if (err) {
      console.error('Error fetching ticket count:', err);
      return next(err);
    }

    // Get the ticket count from the results or set it to zero if no tickets are assigned
    const ticketCount = results[0] ? results[0].ticketCount : 0;

    // Store the ticket count in a variable to make it accessible in the view
    res.locals.openTicketCount = ticketCount;
    next();
  });
};

  
exports.view = (req, res) => {
  // User the connection
  connection.query('SELECT * FROM tickets WHERE status = "active"', (err, rows) => {
    // When done with the connection, release it
    if (!err) {
      let removedUser = req.query.removed;
      res.render('profile', { rows, removedUser });
    } else {
      console.log(err);
    }
    console.log('The data from profile table: \n', rows);
  });
}

/*to view ticket*/
exports.viewuser = (req, res) => {
  const ticketId = req.params.id;

  console.log('Ticket ID:', ticketId);

  // Use the connection
  db.query('SELECT * FROM tickets WHERE id = ?', [ticketId], (err, ticketRows) => {
    if (err) {
      console.log('Database error:', err);
      res.redirect('/search');
      return;
    }

    if (ticketRows.length > 0) {
      const ticket = ticketRows[0];
      
      // Fetch associated comments
      db.query('SELECT * FROM comments WHERE ticket_id = ?', [ticketId], (commentErr, commentRows) => {
        if (commentErr) {
          console.error('Error fetching comments:', commentErr);
          res.status(500).send('Internal Server Error');
          return;
        }

        // Pass ticket and comments data to the view
        res.render('view-ticket', { ticket, comments: commentRows });
      });
    } else {
      console.log('No ticket found');
      res.redirect('/search');
    }
  });
};




exports.isLoggedIn = async (req, res, next) => {
  // console.log(req.cookies);
  if( req.cookies.jwt) {
    try {
      //1) verify the token
      const decoded = await promisify(jwt.verify)(req.cookies.jwt,
      process.env.JWT_SECRET
      );

      console.log(decoded);

      //2) Check if the user still exists
      db.query('SELECT * FROM users WHERE id = ?', [decoded.id], (error, result) => {
        console.log(result);

        if(!result) {
          return next();
        }

        req.user = result[0];
        console.log("user is")
        console.log(req.user);
        return next();

      });
    } catch (error) {
      console.log(error);
      return next();
    }
  } else {
    next();
  }
}











exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if( !email || !password ) {
      return res.status(400).render('login', {
        message: 'Please provide an email and password'
      })
    }

    db.query('SELECT * FROM users WHERE email = ?', [email], async (error, results) => {
      console.log(results);
      if( !results || !(await bcrypt.compare(password, results[0].password)) ) {
        res.status(401).render('login', {
          message: 'Email or Password is incorrect'
        })
      } else {
        const id = results[0].id;

        const token = jwt.sign({ id }, process.env.JWT_SECRET, {
          expiresIn: process.env.JWT_EXPIRES_IN
        });

        console.log("The token is: " + token);

        const cookieOptions = {
          expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
          ),
          httpOnly: true
        }

        res.cookie('jwt', token, cookieOptions );
        res.status(200).redirect("/");
      }

    })

  } catch (error) {
    console.log(error);
  }
}



exports.register=(req, res)=>{
  console.log(req.body);
  
  
  
  const {name, email , password, passwordConfirm} =req.body
  db.query('SELECT email FROM users WHERE email = ?', [email], async (error, results) =>{
      if(error){
          console.log(error);
      }
      if(results.length> 0) {
          return res.render('register', {
              message:'That email is already in use'
          })
          
      }
      else if ( password!==passwordConfirm) {
          return res.render('register',{
              message: 'Passwords do not match'
          });
      }
  
      let hashedPassword = await bcrypt.hash(password, 8);
      console.log(hashedPassword);
  
  
      db.query('INSERT INTO users SET ?', {name: name, email: email, password: hashedPassword, role:'user' }, (error, results) => {
  
        if(error){
            console.log(error);
    
        }
    else {
            console.log(results);
            return res.render('register', {
                message: 'User registered'
            });
        }
    })
  
  
  });
  
      
  }





  exports.addUser = (req, res) => {
    const { name, email, password, role } = req.body;
  
    if (!name || !email || !password || !role) {
      return res.status(400).json({ message: 'Name, email, password, and role are required.' });
    }
  
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        return res.status(500).json({ message: 'Error hashing password.' });
      }
  
      // Insert user into the database
      connection.query(
        'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
        [name, email, hashedPassword, role],
        (err, result) => {
          if (err) {
            return res.status(500).json({ message: 'Error adding user.' });
          }
  
          res.redirect('/user-settings?success=true');
        }
      );
    });
  };
  







exports.fetchUserDetails = (req, res) => {
  const userId = req.params.id;

  // Query the database to fetch user details
  connection.query('SELECT name, email FROM users WHERE id = ?', [userId], (error, userDetails) => {
    if (error) {
      console.error('Error fetching user details:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (userDetails.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Respond with user details in JSON format
    res.json(userDetails[0]);
  });
};








// In your authController.js


// authController.js

exports.getUserDetailsForEdit = (req, res) => {
  const userId = req.params.id; // Get the userId from the route parameters

  if (!userId) {
    return res.status(400).json({ error: 'User ID is required' });
  }

  // Query the database to fetch user details
  connection.query(
    'SELECT id, name, email, role FROM users WHERE id = ?',
    [userId],
    (err, rows) => {
      if (err) {
        console.error('Error fetching user data:', err);
        return res.status(500).json({ error: 'Failed to fetch user data' });
      }

      if (rows.length > 0) {
        const user = rows[0];

        // Prepare the response data
        const userData = {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          isAdmin: user.role === 'admin', // Determine if the user is an admin
        };

        return res.json(userData); // Send the user data as JSON
      } else {
        return res.status(404).json({ error: 'User not found' });
      }
    }
  );
};



// controllers/auth.js

// Fetch the list of users from the database
exports.getUserList = (req, res, next) => {
  // Query to fetch the user list from the database
  connection.query('SELECT id, name FROM users', (error, userList) => {
    if (error) {
      console.error('Error fetching user list:', error);
      return res.status(500).render('reset-password', {
        message: 'Internal server error. Please try again later.',
      });
    }

    console.log('User list:', userList); // Log the retrieved user list
    req.userList = userList; // Attach the user list to the request object
    next(); // Proceed to the next middleware or route
  });
};


exports.getUserListForUserSettings = (req, res, next) => {
  // Fetch users with their roles
  connection.query('SELECT id, name, role FROM users', (error, userList) => {
    if (error) {
      console.error('Error fetching user list:', error);
      return res.status(500).render('user-settings', {
        message: 'Internal server error. Please try again later.',
      });
    }

    console.log('User list:', userList); // Log the retrieved user list
    req.users = userList;  // Save the user list to the request object
    next();  // Pass control to the next middleware or route handler
  });
};


// controllers/auth.js

// Function to reset a user's password






  







exports.resetPassword = async (req, res) => {
  const { selectedUser, newPassword, confirmPassword } = req.body;

  // Validate newPassword and confirmPassword
  if (
    typeof newPassword !== 'string' ||
    typeof confirmPassword !== 'string' ||
    newPassword !== confirmPassword ||
    newPassword.trim() === ''
  ) {
    return res.render('reset-password', {
      message: 'Invalid or mismatched passwords'
    });
  }

  try {
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 8);

    // Update the user's password in your database
    await db.query(
      'UPDATE users SET password = ? WHERE id = ?',
      [hashedPassword, selectedUser]
    );

    // Render the reset-password page with a success message
    return res.render('reset-password', {
      successMessage: 'Password reset successfully'
    });
  } catch (error) {
    console.error('Error resetting password:', error);
    return res.status(500).send('Internal Server Error');
  }
};







exports.deleteTicket = (req, res) => {
  const ticketId = req.params.id;

  // Use the DELETE SQL statement to remove the ticket from the database
  connection.query('DELETE FROM tickets WHERE id = ?', [ticketId], (err, result) => {
    if (!err) {
      // Check if any rows were affected (indicating successful deletion)
      if (result.affectedRows > 0) {
        // If the request is AJAX, send a JSON response
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
          res.json({ message: 'Ticket successfully deleted.' });
        } else {
          // If it's a regular request, redirect to the open tickets page with a success message
          let removedTicket = encodeURIComponent('Ticket successfully deleted.');
          res.redirect('/OpenTickets?success=' + removedTicket);
        }
      } else {
        // If no rows were affected, the ticket may not exist
        res.status(404).json({ error: 'Ticket not found.' });
      }
    } else {
      console.error(err);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });
};









/*

exports.delete = (req, res) => {

  connection.query('UPDATE tickets SET status = ? WHERE id = ?', ['removed', req.params.id], (err, rows) => {
    if (!err) {let removedUser = encodeURIComponent('User successeflly removed.');
    res.redirect('/opentickets?removed=' + removedUser);
      
    } else {
      console.log(err);
    }
    console.log('The data from tickets table are: \n', rows);
  });

}*/



  

exports.logout = async (req, res) => {
  // Clear the JWT cookie
  res.clearCookie('jwt', { httpOnly: true });
  
  // Redirect to the login page
  res.status(200).redirect('/login');
}