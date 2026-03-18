let userModel = require('../schemas/users');
let bcrypt = require('bcrypt');

module.exports = {
  CreateAnUser: async function (username, password, email, role,
    fullName, avatarUrl, status, loginCount) {
    let newItem = new userModel({
      username: username,
      password: password,
      email: email,
      fullName: fullName,
      avatarUrl: avatarUrl,
      status: status,
      role: role,
      loginCount: loginCount
    });
    await newItem.save();
    return newItem;
  },

  GetAnUserByUsername: async function (username) {
    return await userModel.findOne({
      isDeleted: false,
      username: username
    });
  },

  GetAnUserById: async function (id) {
    return await userModel.findOne({
      _id: id,
      isDeleted: false
    });
  },

  /**
   * Đổi mật khẩu người dùng
   * Kiểm tra oldPassword khớp với mật khẩu hiện tại trước khi cập nhật
   */
  ChangePassword: async function (userId, oldPassword, newPassword) {
    let user = await userModel.findOne({ _id: userId, isDeleted: false });

    if (!user) {
      throw new Error('Nguoi dung khong ton tai');
    }

    let isOldPasswordValid = bcrypt.compareSync(oldPassword, user.password);
    if (!isOldPasswordValid) {
      throw new Error('Mat khau cu khong dung');
    }

    // Schema pre-save hook sẽ tự động hash newPassword
    user.password = newPassword;
    await user.save();

    return { message: 'Doi mat khau thanh cong' };
  }
};