import { AuthService } from './../../auth/services/auth.service';
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-admin-header',
  templateUrl: './admin-header.component.html',
  styleUrls: ['./admin-header.component.css']
})
export class AdminHeaderComponent implements OnInit {

  constructor(private auth: AuthService) { }

  ngOnInit() {
    // console.log(this.auth.getUser());
  }

  logout(e) {
    e.preventDefault(); // Não chama o link
    this.auth.logout();
  }

}
