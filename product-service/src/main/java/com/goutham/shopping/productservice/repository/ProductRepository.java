package com.goutham.shopping.productservice.repository;

import com.goutham.shopping.productservice.model.Product;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface ProductRepository extends MongoRepository<Product, String> {
}
