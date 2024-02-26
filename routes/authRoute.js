const express = require('express');
const router = express.Router();

const { createUser,
        loginUser,
        getAllUsers, 
        getUserById, 
        deleteUserById, 
        updateUser, 
        refreshToken, 
        logout,
        updatePassword,
        forgottenPasswordToken,
        resetPassword,
        saveAddress,
       } = require('../controllers/userController');
const { authMiddleware} = require('../middlewares/authMiddleware');



router.post('/register', createUser );
router.post('/forgot-pass-token', forgottenPasswordToken);
router.put('/reset-password/:token', resetPassword);

router.put('/password-update', authMiddleware, updatePassword);
router.post('/login', loginUser );
router.get('/all-users', getAllUsers );
router.get('/refresh', refreshToken );
router.get('/logout', logout);



router.get('/:id', authMiddleware, getUserById );
router.put('/edit-user', authMiddleware, updateUser);
router.put("/save-address", authMiddleware, saveAddress);

router.delete('/:id', deleteUserById);





module.exports = router;