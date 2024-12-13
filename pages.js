const dotenv =require('dotenv');
const express = require('express');
const cors =require("cors")
const router = express.Router();
const authController =require('../controllers/auth');
const jwt = require('jsonwebtoken');




const hbs = require('hbs');


router.use(authController.isLoggedIn);
   

/*router.get('/profile:id', authController.delete);*/

// In your router module
router.post('/add-user', authController.isLoggedIn,authController.addUser);

router.post('/submit-comment', authController.submitComment);


router.post('/SubmitTicket', authController.submitticket);

router.get('/reset-password', authController.isLoggedIn,(req, res) => {
  // Fetch the list of users and render the reset-password page
  authController.getUserList(req, res, () => {
    res.render('reset-password', { user: req.userList }); // Use 'user' instead of 'users'
  });
});



router.post('/reset-password', authController.isLoggedIn, authController.resetPassword);


router.get('/OpenTickets', authController.isLoggedIn,authController.openTickets);


router.get('/profile', authController.isLoggedIn,authController.getCountOfOpenTickets, (req, res) => {
  console.log(req.user);
  if( req.user ) {
    res.render('profile', {
      user: req.user
    });
  } else {
    res.redirect('/login');
  }
  
})


router.get('/',authController.isLoggedIn,(req, res)=> {
    res.render('index',{
      user:req.user
    });
})

// Assuming you're using Express.js
router.post('/add-comment', (req, res) => {
  const { ticketId, comment } = req.body;

  // Process the comment (e.g., save it to the database)
  // Return an appropriate response
});



/*router.get('/OpenTickets', authController.viewopen, (req, res) => {
  res.render('OpenTickets', {
    user: req.user,
    tickets: req.openTickets // Pass the fetched open tickets to the view
  });
});*/










//auth delete end //
router.get('/editticket/:id',authController.edit,(req, res)=> {
  res.render('ticket-form',{
    user:req.user
  });
})



/*router.post('/editticket/:id', authController.update, (req, res) => {
  res.render('ticket-form', {
    // Include any data you want to pass to the ticket-form view
    // ...
  });
});*/



exports.form = (req, res) => {
  res.render('add-ticket');
}


router.post('/profile/:id', authController.deleteTicket);








// Handle user deletion using DELETE method
router.delete('/delete-user/:id', authController.isLoggedIn,authController.deleteUser, (req, res) => {
  try {
    const userIdToDelete = req.params.id;

    // Implement logic to delete the user from your database here
    // This will depend on your specific database setup and controller function

    // Send a success response with a message
    res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'An error occurred while deleting the user' });
  }
}); 

router.post('/add-user', authController.isLoggedIn, authController.addUser);




// In your backend routes (e.g., userRoutes.js)









/*
router.post('/auth/SubmitTicket', (req, res) => {
  // ... (your code to insert the ticket into the database)
  // After successfully inserting the ticket, redirect to the submission page with success parameter
  res.redirect('/SubmitTicket?success=true');
});
*/
router.get('/recentlyclosedtickets', authController.recentlyClosedTickets);


// Add a route to update the ticket state for recently closed tickets
router.post('/recentlyClosedTickets', authController.isLoggedIn, (req, res) => {
  recentlyClosedController.updateTicketState(req, res);
});

router.post('/update-ticket-state', authController.isLoggedIn, authController.updateTicketState);
 


router.get('/OpenTickets', authController.viewopen, (req, res) => {
  // Call the getAllTickets function with the user and a callback function
  authController.getAllTickets(req.user, (err, tickets) => {
    if (err) {
      console.error('Error fetching tickets:', err);
      // Handle the error, perhaps by rendering an error page
      res.status(500).send('Internal Server Error');
      return;
    }

    // Now, let's fetch comments for each ticket
    async.map(tickets, (ticket, callback) => {
      db.query('SELECT * FROM comments WHERE ticket_id = ?', [ticket.id], (error, comments) => {
        if (error) {
          console.error('Error fetching comments for ticket:', ticket.id, error);
          // Pass an empty array to indicate no comments or handle the error
          callback(null, { ...ticket, comments: [] });
        } else {
          // Pass the ticket with its associated comments to the callback
          callback(null, { ...ticket, comments });
        }
      });
    }, (mapErr, ticketsWithComments) => {
      if (mapErr) {
        console.error('Error mapping comments to tickets:', mapErr);
        // Handle the error, perhaps by rendering an error page
        res.status(500).send('Internal Server Error');
        return;
      }

      console.log('Fetched tickets with comments:', ticketsWithComments);

      // Render the 'OpenTickets' page and pass the fetched tickets with comments to it
      res.render('OpenTickets', { rows: ticketsWithComments }); // Make sure 'rows' matches the template
    });
  });
});





router.post('/submitticket',(req, res)=> {
  res.render('submitticket');
})


router.get('/submitticket',(req, res)=> {
  res.render('submitticket');
})

router.get('/register',(req, res)=> {
    res.render('register');
})


/*To View ticket */
router.get('/viewuser/:id', authController.viewuser);

router.get('/fetch-user-details/:id',authController.fetchUserDetails, (req, res) => {
  // Fetch user details and send them as JSON
  // ...
  res.json(userDetails);
});

router.post('/update-ticket-state', authController.updateTicketState)



router.get('/reset-password', authController.isLoggedIn,(req, res) => {
  // Load user data from the database and render the reset-password page
  // Ensure you pass the user data to the template
  // You can use your database query or ORM here
  // Example: const users = db.query('SELECT * FROM users');
  // Then render the page with the users data
  res.render('reset-password', { users: users });
});



router.get('/login',(req, res)=> {
  res.render('login');
  
})


router.get('/search', authController.isLoggedIn, authController.searchdes);

router.get('/view-ticket/:ticketid', authController.getTicketWithComments);




router.get('/auth/edit-ticket/:id', authController.edit);

// Route for handling the ticket update logic
router.post('/auth/edit-ticket/:id', authController.updateTicket)

router.get('/ticket-details/:ticketId', function(req, res) {
  // Get ticket details from the database based on ticketId
  Ticket.findById(req.params.ticketId, function(err, ticket) {
      if (err) {
          // Handle error
      } else {
          // Get comments associated with the ticket from the database
          Comment.find({ ticket_id: req.params.ticketId }, function(err, comments) {
              if (err) {
                  // Handle error
              } else {
                  // Render the ticket details page with ticket and comments data
                  res.render('ticket-details', { ticket: ticket, comments: comments });
              }
          });
      }
  });
});


// Route in your router file
router.post('/update-user/:id', (req, res, next) => {
  console.log('Incoming request:', req.params, req.body);
  next();
}, authController.isLoggedIn, authController.isAdmin, authController.updateUser);

router.get('/user-settings', authController.isLoggedIn,authController.getUserList, (req, res) => {
  // Render the 'user-settings' page and pass the fetched user list
  res.render('user-settings', { users: req.userList });
});


// Example route to fetch user details
router.get('/get-user/:id', authController.getUserDetailsForEdit);




module.exports= router;